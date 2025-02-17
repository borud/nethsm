/*
NetHSM

All endpoints expect exactly the specified JSON. Additional properties will cause a Bad Request Error (400). All HTTP errors contain a JSON structure with an explanation of type string. All [base64](https://tools.ietf.org/html/rfc4648#section-4) encoded values are Big Endian. 

API version: v1
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package api

import (
	"encoding/json"
	"bytes"
	"fmt"
)

// checks if the NetworkConfig type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &NetworkConfig{}

// NetworkConfig struct for NetworkConfig
type NetworkConfig struct {
	IpAddress string `json:"ipAddress"`
	Netmask string `json:"netmask"`
	Gateway string `json:"gateway"`
}

type _NetworkConfig NetworkConfig

// NewNetworkConfig instantiates a new NetworkConfig object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewNetworkConfig(ipAddress string, netmask string, gateway string) *NetworkConfig {
	this := NetworkConfig{}
	this.IpAddress = ipAddress
	this.Netmask = netmask
	this.Gateway = gateway
	return &this
}

// NewNetworkConfigWithDefaults instantiates a new NetworkConfig object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewNetworkConfigWithDefaults() *NetworkConfig {
	this := NetworkConfig{}
	return &this
}

// GetIpAddress returns the IpAddress field value
func (o *NetworkConfig) GetIpAddress() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.IpAddress
}

// GetIpAddressOk returns a tuple with the IpAddress field value
// and a boolean to check if the value has been set.
func (o *NetworkConfig) GetIpAddressOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.IpAddress, true
}

// SetIpAddress sets field value
func (o *NetworkConfig) SetIpAddress(v string) {
	o.IpAddress = v
}

// GetNetmask returns the Netmask field value
func (o *NetworkConfig) GetNetmask() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Netmask
}

// GetNetmaskOk returns a tuple with the Netmask field value
// and a boolean to check if the value has been set.
func (o *NetworkConfig) GetNetmaskOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Netmask, true
}

// SetNetmask sets field value
func (o *NetworkConfig) SetNetmask(v string) {
	o.Netmask = v
}

// GetGateway returns the Gateway field value
func (o *NetworkConfig) GetGateway() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Gateway
}

// GetGatewayOk returns a tuple with the Gateway field value
// and a boolean to check if the value has been set.
func (o *NetworkConfig) GetGatewayOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Gateway, true
}

// SetGateway sets field value
func (o *NetworkConfig) SetGateway(v string) {
	o.Gateway = v
}

func (o NetworkConfig) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o NetworkConfig) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["ipAddress"] = o.IpAddress
	toSerialize["netmask"] = o.Netmask
	toSerialize["gateway"] = o.Gateway
	return toSerialize, nil
}

func (o *NetworkConfig) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"ipAddress",
		"netmask",
		"gateway",
	}

	allProperties := make(map[string]interface{})

	err = json.Unmarshal(data, &allProperties)

	if err != nil {
		return err;
	}

	for _, requiredProperty := range(requiredProperties) {
		if _, exists := allProperties[requiredProperty]; !exists {
			return fmt.Errorf("no value given for required property %v", requiredProperty)
		}
	}

	varNetworkConfig := _NetworkConfig{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varNetworkConfig)

	if err != nil {
		return err
	}

	*o = NetworkConfig(varNetworkConfig)

	return err
}

type NullableNetworkConfig struct {
	value *NetworkConfig
	isSet bool
}

func (v NullableNetworkConfig) Get() *NetworkConfig {
	return v.value
}

func (v *NullableNetworkConfig) Set(val *NetworkConfig) {
	v.value = val
	v.isSet = true
}

func (v NullableNetworkConfig) IsSet() bool {
	return v.isSet
}

func (v *NullableNetworkConfig) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableNetworkConfig(val *NetworkConfig) *NullableNetworkConfig {
	return &NullableNetworkConfig{value: val, isSet: true}
}

func (v NullableNetworkConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableNetworkConfig) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


