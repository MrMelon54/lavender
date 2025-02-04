package conf

import (
	"github.com/1f349/lavender/issuer"
)

type Conf struct {
	Listen      string             `yaml:"listen"`
	BaseUrl     string             `yaml:"baseUrl"`
	ServiceName string             `yaml:"serviceName"`
	Issuer      string             `yaml:"issuer"`
	Kid         string             `yaml:"kid"`
	SsoServices []issuer.SsoConfig `yaml:"ssoServices"`
}
