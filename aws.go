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

import (
	"errors"
	"fmt"
	"sync"
	"time"

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
	timestamp time.Time          // The last time the maps were refreshed
	svc       *dynamodb.DynamoDB // Reference to the creators table
	common
}

// Item is the dynamodb table item representation of a Creator
type Item struct {
	Owidcreator string
	Domain      string
	PrivateKey  string
	PublicKey   string
	Name        string
}

// NewAWS creates a new instance of the AWS structure
func NewAWS() (*AWS, error) {
	var a AWS
	var sess *session.Session

	// Configure session with credentials from .aws/credentials or env and
	// region from .aws/config or env
	sess = session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	if sess == nil {
		return nil, errors.New("AWS session is nil")
	}
	a.svc = dynamodb.New(sess)

	_, err := a.awsCreateCreatorsTable()
	if err != nil {
		return nil, err
	}

	a.mutex = &sync.Mutex{}
	err = a.refresh()
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (a *AWS) setCreator(c *Creator) error {
	item := Item{
		creatorsTablePartitionKey,
		c.domain,
		c.privateKey,
		c.publicKey,
		c.name}

	av, err := dynamodbattribute.MarshalMap(item)
	if err != nil {
		fmt.Println("Got error marshalling new creator item:")
		return err
	}

	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(creatorsTableName),
	}

	_, err = a.svc.PutItem(input)
	if err != nil {
		fmt.Println("Got error calling PutItem:")
		return err
	}

	return nil
}

// GetCreator gets creator for domain from internal map, updating the internal
// map if the creator is not in the map.
func (a *AWS) GetCreator(domain string) (*Creator, error) {
	c, err := a.common.getCreator(domain)
	if err != nil {
		return nil, err
	}
	if c == nil {
		err = a.refresh()
		if err != nil {
			return nil, err
		}
		c, err = a.common.getCreator(domain)
	}
	return c, err
}

func (a *AWS) getCreatorDirect(domain string) (*Creator, error) {
	result, err := a.svc.GetItem(&dynamodb.GetItemInput{
		TableName: aws.String(creatorsTableName),
		Key: map[string]*dynamodb.AttributeValue{
			creatorsTablePartitionKeyName: {
				S: aws.String(creatorsTablePartitionKey),
			},
			creatorsTableDomainAttribute: {
				S: aws.String(domain),
			},
		},
	})
	if err != nil {
		return nil, err
	}

	if result.Item == nil {
		msg := "Could not find '" + domain + "'"
		return nil, errors.New(msg)
	}

	item := Item{}

	err = dynamodbattribute.UnmarshalMap(result.Item, &item)
	if err != nil {
		panic(fmt.Sprintf("Failed to unmarshal Record, %v", err))
	}

	c := newCreator(
		item.Domain,
		item.PrivateKey,
		item.PublicKey,
		item.Name)
	return c, nil
}

func (a *AWS) awsCreateCreatorsTable() (*dynamodb.CreateTableOutput, error) {
	input := &dynamodb.CreateTableInput{
		AttributeDefinitions: []*dynamodb.AttributeDefinition{
			{
				AttributeName: aws.String(creatorsTablePartitionKeyName),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String(creatorsTableDomainAttribute),
				AttributeType: aws.String("S"),
			},
		},
		KeySchema: []*dynamodb.KeySchemaElement{
			{
				AttributeName: aws.String(creatorsTablePartitionKeyName),
				KeyType:       aws.String("HASH"),
			},
			{
				AttributeName: aws.String(creatorsTableDomainAttribute),
				KeyType:       aws.String("RANGE"),
			},
		},
		BillingMode: aws.String("PAY_PER_REQUEST"),
		TableName:   aws.String(creatorsTableName),
	}

	o, err := a.svc.CreateTable(input)
	if err != nil {
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
			TableName: aws.String(creatorsTableName),
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

func (a *AWS) refresh() error {
	// Fetch the creators
	cs, err := a.fetchCreators()
	if err != nil {
		return err
	}
	// In a single atomic operation update the reference to the creators.
	a.mutex.Lock()
	a.creators = cs
	a.mutex.Unlock()

	return nil
}

func (a *AWS) fetchCreators() (map[string]*Creator, error) {

	cs := make(map[string]*Creator)

	filt := expression.Name(creatorsTablePartitionKeyName).Equal(expression.Value(creatorsTablePartitionKey))

	proj := expression.NamesList(expression.Name(creatorsTableDomainAttribute),
		expression.Name("PrivateKey"),
		expression.Name("PublicKey"),
		expression.Name("Name"))

	expr, err := expression.NewBuilder().WithFilter(filt).WithProjection(proj).Build()
	if err != nil {
		fmt.Println("Got error building expression:")
		fmt.Println(err.Error())
		return nil, err
	}

	params := &dynamodb.ScanInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 aws.String(creatorsTableName),
	}

	// Make the DynamoDB Query API call
	result, err := a.svc.Scan(params)
	if err != nil {
		fmt.Println("Query API call failed:")
		fmt.Println((err.Error()))
		return nil, err
	}

	for _, i := range result.Items {
		item := Item{}

		err = dynamodbattribute.UnmarshalMap(i, &item)
		if err != nil {
			fmt.Println("Got error un-marshalling:")
			fmt.Println(err.Error())
			return nil, err
		}

		cs[item.Domain] = newCreator(
			item.Domain,
			item.PrivateKey,
			item.PublicKey,
			item.Name)
	}

	return cs, nil
}
