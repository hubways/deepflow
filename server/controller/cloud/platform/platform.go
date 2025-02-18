/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package platform

import (
	"errors"
	"fmt"

	"github.com/deepflowio/deepflow/server/controller/cloud/aliyun"
	"github.com/deepflowio/deepflow/server/controller/cloud/aws"
	"github.com/deepflowio/deepflow/server/controller/cloud/baidubce"
	"github.com/deepflowio/deepflow/server/controller/cloud/config"
	"github.com/deepflowio/deepflow/server/controller/cloud/filereader"
	"github.com/deepflowio/deepflow/server/controller/cloud/genesis"
	"github.com/deepflowio/deepflow/server/controller/cloud/huawei"
	"github.com/deepflowio/deepflow/server/controller/cloud/kubernetes"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/cloud/qingcloud"
	"github.com/deepflowio/deepflow/server/controller/cloud/tencent"
	"github.com/deepflowio/deepflow/server/controller/cloud/volcengine"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("cloud.platform")

type Platform interface {
	CheckAuth() error
	GetCloudData() (model.Resource, error)
	ClearDebugLog()
}

func NewPlatform(domain metadbmodel.Domain, cfg config.CloudConfig, db *metadb.DB) (Platform, error) {
	var platform Platform
	var err error

	switch domain.Type {
	case common.ALIYUN:
		platform, err = aliyun.NewAliyun(db.ORGID, domain, cfg)
	case common.AWS:
		platform, err = aws.NewAws(db.ORGID, domain, cfg)
	case common.AGENT_SYNC:
		platform, err = genesis.NewGenesis(db.ORGID, domain, cfg)
	case common.QINGCLOUD:
		platform, err = qingcloud.NewQingCloud(db.ORGID, domain, cfg)
	case common.BAIDU_BCE:
		platform, err = baidubce.NewBaiduBce(db.ORGID, domain, cfg)
	case common.TENCENT:
		platform, err = tencent.NewTencent(db.ORGID, domain, cfg)
	case common.KUBERNETES:
		platform, err = kubernetes.NewKubernetes(db.ORGID, domain)
	case common.HUAWEI:
		platform, err = huawei.NewHuaWei(db.ORGID, domain, cfg)
	case common.FILEREADER:
		platform, err = filereader.NewFileReader(db.ORGID, domain)
	case common.VOLCENGINE:
		platform, err = volcengine.NewVolcEngine(db.ORGID, domain, cfg)
	// TODO: other platform
	default:
		return nil, errors.New(fmt.Sprintf("domain type (%d) not supported", domain.Type))
	}
	return platform, err
}
