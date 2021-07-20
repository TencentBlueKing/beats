// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// +build !integration

package log

import (
	"fmt"
	"github.com/elastic/beats/filebeat/input/file"
	"github.com/elastic/beats/libbeat/common"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestReuseReadLine(t *testing.T) {
	absPath, err := filepath.Abs("../../tests/files/logs/")
	// All files starting with tmp are ignored
	logFile := absPath + "/tmp" + strconv.Itoa(rand.Int()) + ".log"

	assert.NotNil(t, absPath)
	assert.Nil(t, err)

	if err != nil {
		t.Fatalf("Error creating the absolute path: %s", absPath)
	}

	fd, err := os.Create(logFile)
	if err != nil {
		panic(err)
	}
	defer fd.Close()
	defer os.Remove(logFile)

	assert.Nil(t, err)
	assert.NotNil(t, fd)

	firstLineString := "9Characte"
	secondLineString := "This is line 2"
	thirdLineString := "This is line 3"

	length, err := fd.WriteString(firstLineString + "\n")
	assert.Nil(t, err)
	assert.NotNil(t, length)

	length, err = fd.WriteString(secondLineString + "\n")
	assert.Nil(t, err)
	assert.NotNil(t, length)

	length, err = fd.WriteString(thirdLineString + "\n" + secondLineString + "\n")
	assert.Nil(t, err)
	assert.NotNil(t, length)
	err = fd.Sync()
	if err != nil {
		t.Logf("write file err: %v", err)
		return
	}
	_, err = os.Stat(logFile)
	if err != nil {
		t.Logf("get file err: %v", err)
		return
	}

	wg := &sync.WaitGroup{}

	harvesterNums := 100
	wg.Add(harvesterNums)

	for i := 0; i < harvesterNums; i++ {
		go startHarvester(t, i, wg, logFile, firstLineString, secondLineString, thirdLineString)
	}

	wg.Wait()
}

func startHarvester(
	t *testing.T,
	id int,
	wg *sync.WaitGroup,
	logFile string,
	firstLineString string,
	secondLineString string,
	thirdLineString string,
) {
	var fileReader *ReuseHarvester
	defer func() {
		t.Logf("harvester-%d is stopped", id)
		wg.Done()
	}()
	h1, err := getHarvester(logFile, 0)
	if err != nil {
		t.Logf("harvester-%d get reader err: %v", id, err)
		return
	}
	t.Logf("harvester-%d is trying to get the reader", id)

	time.Sleep(time.Duration(rand.Intn(100)) * time.Microsecond)

	fileReader, err = NewReuseHarvester(h1.id, h1.config, h1.state)
	if err != nil {
		panic(err)
	}
	t.Logf("harvester-%d has get the reader", id)

	// get first line
	message, err := fileReader.Next()
	assert.Equal(
		t,
		fmt.Sprintf("[%d]%s", id, firstLineString),
		fmt.Sprintf("[%d]%s", id, string(message.Content)))
	t.Logf("harvester-%d has get first line", id)

	// get second line
	message, err = fileReader.Next()
	assert.Equal(
		t,
		fmt.Sprintf("[%d]%s", id, secondLineString),
		fmt.Sprintf("[%d]%s", id, string(message.Content)))
	t.Logf("harvester-%d has get second line", id)

	// get third line
	message, err = fileReader.Next()
	assert.Equal(
		t,
		fmt.Sprintf("[%d]%s", id, thirdLineString),
		fmt.Sprintf("[%d]%s", id, string(message.Content)))
	t.Logf("harvester-%d has get third line", id)
	t.Logf("harvester-%d trying to stop", id)
	fileReader.Stop()
}

func getHarvester(filePath string, offset int64) (*Harvester, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	vars := map[string]interface{}{
		"type":         "log",
		"paths":        []string{filePath},
		"encoding":     "utf-8",
		"reuse_reader": true,
	}
	rawConfig, err := common.NewConfigFrom(vars)
	if err != nil {
		return nil, err
	}

	h := &Harvester{
		id:     id,
		config: defaultConfig,
		states: file.NewStates(),
	}

	if err := rawConfig.Unpack(&h.config); err != nil {
		panic(err)
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}
	fileState := file.NewState(fileInfo, filePath, "log", nil)
	fileState.Offset = offset
	h.state = fileState
	return h, nil
}
