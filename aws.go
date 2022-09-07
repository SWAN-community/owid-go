/* ****************************************************************************
 * Copyright 2020 51 Degrees Mobile Experts Limited (51degrees.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 * ***************************************************************************/

package owid

// cspell:ignore awserr dynamodbattribute filt
import (
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
)

// Connect to AWS DynamoDB. Concrete implementation of store.go

// AWS is a implementation of owid.Store for Amazon's Dynamo DB storage.
type AWS struct {
	storeBase
	svc *dynamodb.DynamoDB // Reference to the creators table
}

// NewAWS creates a new instance of the AWS structure
// cspell:ignore sess
func NewAWS() (*AWS, error) {
	var a AWS

	// Configure session with credentials from .aws/credentials or env and
	// region from .aws/config or env
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	if sess == nil {
		return nil, fmt.Errorf("AWS session is nil")
	}
	a.svc = dynamodb.New(sess)

	_, err := a.awsCreateKeysTable()
	if err != nil {
		return nil, fmt.Errorf("create keys table: %w", err)
	}

	_, err = a.awsCreateSignersTable()
	if err != nil {
		return nil, fmt.Errorf("create signers table: %w", err)
	}

	a.mutex = &sync.Mutex{}
	err = a.refresh()
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// GetSigner gets signer for domain from internal map, updating the internal
// map from AWS if the signer is not in the map.
func (a *AWS) GetSigner(domain string) (*Signer, error) {
	s, err := a.getSigner(domain)
	if err != nil {
		return nil, err
	}
	if s == nil {
		err = a.refresh()
		if err != nil {
			return nil, err
		}
		s, err = a.getSigner(domain)
	}
	return s, err
}

func (a *AWS) addItem(tableName string, i interface{}) error {
	av, err := dynamodbattribute.MarshalMap(i)
	if err != nil {
		return fmt.Errorf("MarshalMap: %w", err)
	}

	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(tableName),
	}

	_, err = a.svc.PutItem(input)
	if err != nil {
		return fmt.Errorf("PutItem: %s %w", tableName, err)
	}

	return nil
}

func (a *AWS) addKeys(d string, k *Keys) error {
	return a.addItem(keysTableName, &KeysWithDomain{
		Domain: d,
		Keys:   k})
}

func (a *AWS) addSigner(s *Signer) error {
	err := a.addItem(signersTableName, s)
	if err != nil {
		return err
	}
	for _, k := range s.Keys {
		err = a.addKeys(s.Domain, k)
		if err != nil {
			return err
		}
	}
	return nil
}

// addTable adds the table to the AWS service and verifies that it has been
// created correctly.
func (a *AWS) addTable(
	input *dynamodb.CreateTableInput) (*dynamodb.CreateTableOutput, error) {
	o, err := a.svc.CreateTable(input)
	if err != nil {
		// cspell:ignore aerr
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case dynamodb.ErrCodeTableAlreadyExistsException:
				break
			case dynamodb.ErrCodeResourceInUseException:
				break
			default:
				return o, err
			}
		} else {
			return o, err
		}
	}

	for {
		input := &dynamodb.DescribeTableInput{
			TableName: aws.String(*input.TableName),
		}
		result, err := a.svc.DescribeTable(input)
		if err != nil {
			return nil, err
		}
		if *result.Table.TableStatus == "ACTIVE" {
			break
		}
	}

	return o, nil
}

func (a *AWS) awsCreateKeysTable() (*dynamodb.CreateTableOutput, error) {
	return a.addTable(&dynamodb.CreateTableInput{
		AttributeDefinitions: []*dynamodb.AttributeDefinition{
			{
				AttributeName: aws.String("Domain"),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String("Created"),
				AttributeType: aws.String("S"),
			},
		},
		KeySchema: []*dynamodb.KeySchemaElement{
			{
				AttributeName: aws.String("Domain"),
				KeyType:       aws.String("HASH"),
			},
			{
				AttributeName: aws.String("Created"),
				KeyType:       aws.String("RANGE"),
			},
		},
		BillingMode: aws.String("PAY_PER_REQUEST"),
		TableName:   aws.String(keysTableName),
	})
}

func (a *AWS) awsCreateSignersTable() (*dynamodb.CreateTableOutput, error) {
	return a.addTable(&dynamodb.CreateTableInput{
		AttributeDefinitions: []*dynamodb.AttributeDefinition{
			{
				AttributeName: aws.String("Domain"),
				AttributeType: aws.String("S"),
			}},
		KeySchema: []*dynamodb.KeySchemaElement{
			{
				AttributeName: aws.String("Domain"),
				KeyType:       aws.String("RANGE"),
			}},
		BillingMode: aws.String("PAY_PER_REQUEST"),
		TableName:   aws.String(signersTableName),
	})
}

func (a *AWS) refresh() error {
	// Fetch the signers
	s, err := a.fetchSigners()
	if err != nil {
		return err
	}

	// In a single atomic operation update the reference to the creators.
	a.mutex.Lock()
	a.signers = s
	a.mutex.Unlock()

	return nil
}

func (a *AWS) fetchSigners() (map[string]*Signer, error) {

	signers := make(map[string]*Signer)

	// Get the signers from AWS.
	s, err := a.scanSigners()
	if err != nil {
		return nil, fmt.Errorf("scanning signers: %w", err)
	}

	// Loop through the results adding them to the signers map.
	for _, i := range s.Items {

		// Create the new signer from the item read.
		var n Signer
		err := dynamodbattribute.UnmarshalMap(i, &n)
		if err != nil {
			return nil, fmt.Errorf("unmarshalling signer: %w", err)
		}

		// Adds the keys for the signer.
		err = a.addKeysToSigner(&n)
		if err != nil {
			return nil, err
		}

		signers[n.Domain] = &n
	}

	return signers, nil
}

func (a *AWS) addKeysToSigner(s *Signer) error {

	// Scan the table for the keys that match the domain.
	k, err := a.scanKeys(s.Domain)
	if err != nil {
		return fmt.Errorf("scanning keys: %w", err)
	}

	// Make the array of keys large enough to include all the items.
	s.Keys = make([]*Keys, *k.Count)

	// Unmarshall the keys into the signer's array of keys.
	for i, a := range k.Items {
		var n Keys
		err := dynamodbattribute.UnmarshalMap(a, &n)
		if err != nil {
			return fmt.Errorf(
				"unmarshalling keys for domain '%s': %w",
				s.Domain,
				err)
		}
		s.Keys[i] = &n
	}
	s.SortKeys()

	return nil
}

// scanKeys scans the keys for the given domain.
func (a *AWS) scanKeys(domain string) (*dynamodb.ScanOutput, error) {
	expr, err := expression.NewBuilder().WithFilter(
		expression.Name("Domain").Equal(
			expression.Value(domain))).WithProjection(
		expression.NamesList(
			expression.Name("Created"),
			expression.Name("PublicKey"),
			expression.Name("PrivateKey"))).Build()
	if err != nil {
		return nil, fmt.Errorf("building keys expression: %w", err)
	}
	return a.scan(expr, signersTableName)
}

// scanSigners scans all the available signers in the table.
func (a *AWS) scanSigners() (*dynamodb.ScanOutput, error) {
	expr, err := expression.NewBuilder().WithProjection(
		expression.NamesList(
			expression.Name("Domain"),
			expression.Name("Name"),
			expression.Name("TermsURL"))).Build()
	if err != nil {
		return nil, fmt.Errorf("building signers expression: %w", err)
	}
	return a.scan(expr, signersTableName)
}

func (a *AWS) scan(
	expr expression.Expression,
	tableName string) (*dynamodb.ScanOutput, error) {
	result, err := a.svc.Scan(&dynamodb.ScanInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 aws.String(tableName)})
	if err != nil {
		return nil, fmt.Errorf("query API call failed: %w", err)
	}
	return result, nil
}
