/*
    _____           _____   _____   ____          ______  _____  ------
   |     |  |      |     | |     | |     |     | |       |            |
   |     |  |      |     | |     | |     |     | |       |            |
   | --- |  |      |     | |-----| |---- |     | |-----| |-----  ------
   |     |  |      |     | |     | |     |     |       | |       |
   | ____|  |_____ | ____| | ____| |     |_____|  _____| |_____  |_____


   Licensed under the MIT License <http://opensource.org/licenses/MIT>.

   Copyright © 2020-2022 Microsoft Corporation. All rights reserved.
   Author : <blobfusedev@microsoft.com>

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE
*/

package libfuse

import (
	"blobfuse2/common"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/suite"
)

// Tests the default configuration of libfuse
func (suite *libfuseTestSuite) TestDefault() {
	defer suite.cleanupTest()
	suite.assert.Equal(suite.libfuse.Name(), "libfuse")
	suite.assert.Empty(suite.libfuse.mountPath)
	suite.assert.False(suite.libfuse.readOnly)
	suite.assert.False(suite.libfuse.traceEnable)
	suite.assert.False(suite.libfuse.allowOther)
	suite.assert.Equal(suite.libfuse.dirPermission, uint(common.DefaultDirectoryPermissionBits))
	suite.assert.Equal(suite.libfuse.filePermission, uint(common.DefaultFilePermissionBits))
	suite.assert.Equal(suite.libfuse.entryExpiration, uint32(120))
	suite.assert.Equal(suite.libfuse.attributeExpiration, uint32(120))
	suite.assert.Equal(suite.libfuse.negativeTimeout, uint32(120))
}

func (suite *libfuseTestSuite) TestConfig() {
	defer suite.cleanupTest()
	suite.cleanupTest() // clean up the default libfuse generated
	config := "allow-other: true\nread-only: true\nlibfuse:\n  default-permission: 0777\n  attribute-expiration-sec: 60\n  entry-expiration-sec: 60\n  negative-entry-expiration-sec: 60\n  fuse-trace: true\n"
	suite.setupTestHelper(config) // setup a new libfuse with a custom config (clean up will occur after the test as usual)

	suite.assert.Equal(suite.libfuse.Name(), "libfuse")
	suite.assert.Empty(suite.libfuse.mountPath)
	suite.assert.True(suite.libfuse.readOnly)
	suite.assert.True(suite.libfuse.traceEnable)
	suite.assert.True(suite.libfuse.allowOther)
	suite.assert.Equal(suite.libfuse.dirPermission, uint(fs.FileMode(0777)))
	suite.assert.Equal(suite.libfuse.filePermission, uint(fs.FileMode(0777)))
	suite.assert.Equal(suite.libfuse.entryExpiration, uint32(60))
	suite.assert.Equal(suite.libfuse.attributeExpiration, uint32(60))
	suite.assert.Equal(suite.libfuse.negativeTimeout, uint32(60))
}

func (suite *libfuseTestSuite) TestConfigZero() {
	defer suite.cleanupTest()
	suite.cleanupTest() // clean up the default libfuse generated
	config := "allow-other: true\nread-only: true\nlibfuse:\n  default-permission: 0777\n  attribute-expiration-sec: 0\n  entry-expiration-sec: 0\n  negative-entry-expiration-sec: 0\n  fuse-trace: true\n"
	suite.setupTestHelper(config) // setup a new libfuse with a custom config (clean up will occur after the test as usual)

	suite.assert.Equal(suite.libfuse.Name(), "libfuse")
	suite.assert.Empty(suite.libfuse.mountPath)
	suite.assert.True(suite.libfuse.readOnly)
	suite.assert.True(suite.libfuse.traceEnable)
	suite.assert.True(suite.libfuse.allowOther)
	suite.assert.Equal(suite.libfuse.dirPermission, uint(fs.FileMode(0777)))
	suite.assert.Equal(suite.libfuse.filePermission, uint(fs.FileMode(0777)))
	suite.assert.Equal(suite.libfuse.entryExpiration, uint32(0))
	suite.assert.Equal(suite.libfuse.attributeExpiration, uint32(0))
	suite.assert.Equal(suite.libfuse.negativeTimeout, uint32(0))
}

// getattr

func (suite *libfuseTestSuite) TestMkDir() {
	testMkDir(suite)
}

func (suite *libfuseTestSuite) TestMkDirError() {
	testMkDirError(suite)
}

// readdir

func (suite *libfuseTestSuite) TestRmDir() {
	testRmDir(suite)
}

func (suite *libfuseTestSuite) TestRmDirNotEmpty() {
	testRmDirNotEmpty(suite)
}

func (suite *libfuseTestSuite) TestRmDirError() {
	testRmDirError(suite)
}

func (suite *libfuseTestSuite) TestCreate() {
	testCreate(suite)
}

func (suite *libfuseTestSuite) TestCreateError() {
	testCreateError(suite)
}

func (suite *libfuseTestSuite) TestOpen() {
	testOpen(suite)
}

func (suite *libfuseTestSuite) TestOpenSyncFlag() {
	testOpenSyncFlag(suite)
}

func (suite *libfuseTestSuite) TestOpenNotExists() {
	testOpenNotExists(suite)
}

func (suite *libfuseTestSuite) TestOpenError() {
	testOpenError(suite)
}

// read

// write

// flush

func (suite *libfuseTestSuite) TestTruncate() {
	testTruncate(suite)
}

func (suite *libfuseTestSuite) TestTruncateError() {
	testTruncateError(suite)
}

// release

func (suite *libfuseTestSuite) TestUnlink() {
	testUnlink(suite)
}

func (suite *libfuseTestSuite) TestUnlinkNotExists() {
	testUnlinkNotExists(suite)
}

func (suite *libfuseTestSuite) TestUnlinkError() {
	testUnlinkError(suite)
}

// rename

func (suite *libfuseTestSuite) TestSymlink() {
	testSymlink(suite)
}

func (suite *libfuseTestSuite) TestSymlinkError() {
	testSymlinkError(suite)
}

func (suite *libfuseTestSuite) TestReadLink() {
	testReadLink(suite)
}

func (suite *libfuseTestSuite) TestReadLinkNotExists() {
	testReadLinkNotExists(suite)
}

func (suite *libfuseTestSuite) TestReadLinkError() {
	testReadLinkError(suite)
}

func (suite *libfuseTestSuite) TestFsync() {
	testFsync(suite)
}

func (suite *libfuseTestSuite) TestFsyncHandleError() {
	testFsyncHandleError(suite)
}

func (suite *libfuseTestSuite) TestFsyncError() {
	testFsyncError(suite)
}

func (suite *libfuseTestSuite) TestFsyncDir() {
	testFsyncDir(suite)
}

func (suite *libfuseTestSuite) TestFsyncDirError() {
	testFsyncDirError(suite)
}

func (suite *libfuseTestSuite) TestChmod() {
	testChmod(suite)
}

func (suite *libfuseTestSuite) TestChmodNotExists() {
	testChmodNotExists(suite)
}

func (suite *libfuseTestSuite) TestChmodError() {
	testChmodError(suite)
}

func (suite *libfuseTestSuite) TestChown() {
	testChown(suite)
}

func (suite *libfuseTestSuite) TestUtimens() {
	testUtimens(suite)
}

// In order for 'go test' to run this suite, we need to create
// a normal test function and pass our suite to suite.Run
func TestLibfuseTestSuite(t *testing.T) {
	suite.Run(t, new(libfuseTestSuite))
}