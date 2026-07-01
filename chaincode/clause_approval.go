package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// ClauseContract defines the Smart Contract structure
type ClauseContract struct {
	contractapi.Contract
}

// Clause represents an approved clause stored on the blockchain
type Clause struct {
	ContractID string `json:"contract_id"`
	Position   int    `json:"position"`
	Label      string `json:"label"`
	Text       string `json:"text"`
	SHA256Hash string `json:"sha256_hash"`
}

// QueryAuditLog represents a contract query event logged on the blockchain
type QueryAuditLog struct {
	QueryID      string `json:"query_id"`
	ContractID   string `json:"contract_id"`
	Query        string `json:"query"`
	ResponseHash string `json:"response_hash"`
	Timestamp    string `json:"timestamp"`
}

// StoreClause stores a new clause and its hash in the world state
func (c *ClauseContract) StoreClause(ctx contractapi.TransactionContextInterface, contractID string, position int, label string, text string, sha256Hash string) error {
	clause := Clause{
		ContractID: contractID,
		Position:   position,
		Label:      label,
		Text:       text,
		SHA256Hash: sha256Hash,
	}

	clauseBytes, err := json.Marshal(clause)
	if err != nil {
		return fmt.Errorf("failed to marshal clause: %v", err)
	}

	key := fmt.Sprintf("CLAUSE_%s_%s", contractID, label)
	return ctx.GetStub().PutState(key, clauseBytes)
}

// GetClause retrieves a clause by contract ID and label from the world state
func (c *ClauseContract) GetClause(ctx contractapi.TransactionContextInterface, contractID string, label string) (*Clause, error) {
	key := fmt.Sprintf("CLAUSE_%s_%s", contractID, label)
	clauseBytes, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if clauseBytes == nil {
		return nil, fmt.Errorf("clause with label %s in contract %s does not exist", label, contractID)
	}

	var clause Clause
	err = json.Unmarshal(clauseBytes, &clause)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal clause bytes: %v", err)
	}

	return &clause, nil
}

// VerifyClauseHash verifies that the provided hash matches the ledger's hash
func (c *ClauseContract) VerifyClauseHash(ctx contractapi.TransactionContextInterface, contractID string, label string, currentHash string) (bool, error) {
	clause, err := c.GetClause(ctx, contractID, label)
	if err != nil {
		return false, err
	}
	return clause.SHA256Hash == currentHash, nil
}

// LogQuery records a contract query event on the blockchain for auditing purposes
func (c *ClauseContract) LogQuery(ctx contractapi.TransactionContextInterface, queryID string, contractID string, query string, responseHash string, timestamp string) error {
	logEntry := QueryAuditLog{
		QueryID:      queryID,
		ContractID:   contractID,
		Query:        query,
		ResponseHash: responseHash,
		Timestamp:    timestamp,
	}

	logBytes, err := json.Marshal(logEntry)
	if err != nil {
		return fmt.Errorf("failed to marshal audit log: %v", err)
	}

	key := fmt.Sprintf("QUERY_LOG_%s", queryID)
	return ctx.GetStub().PutState(key, logBytes)
}

// GetQueryLog retrieves a query audit log by query ID
func (c *ClauseContract) GetQueryLog(ctx contractapi.TransactionContextInterface, queryID string) (*QueryAuditLog, error) {
	key := fmt.Sprintf("QUERY_LOG_%s", queryID)
	logBytes, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if logBytes == nil {
		return nil, fmt.Errorf("query log with ID %s does not exist", queryID)
	}

	var logEntry QueryAuditLog
	err = json.Unmarshal(logBytes, &logEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal audit log bytes: %v", err)
	}

	return &logEntry, nil
}

func main() {
	cc, err := contractapi.NewChaincode(&ClauseContract{})
	if err != nil {
		panic(fmt.Sprintf("error creating clause chaincode: %v", err))
	}

	if err := cc.Start(); err != nil {
		panic(fmt.Sprintf("error starting clause chaincode: %v", err))
	}
}
