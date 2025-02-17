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

// checks if the LoggingConfig type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &LoggingConfig{}

// LoggingConfig struct for LoggingConfig
type LoggingConfig struct {
	IpAddress string `json:"ipAddress"`
	Port int32 `json:"port"`
	LogLevel LogLevel `json:"logLevel"`
}

type _LoggingConfig LoggingConfig

// NewLoggingConfig instantiates a new LoggingConfig object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewLoggingConfig(ipAddress string, port int32, logLevel LogLevel) *LoggingConfig {
	this := LoggingConfig{}
	this.IpAddress = ipAddress
	this.Port = port
	this.LogLevel = logLevel
	return &this
}

// NewLoggingConfigWithDefaults instantiates a new LoggingConfig object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewLoggingConfigWithDefaults() *LoggingConfig {
	this := LoggingConfig{}
	return &this
}

// GetIpAddress returns the IpAddress field value
func (o *LoggingConfig) GetIpAddress() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.IpAddress
}

// GetIpAddressOk returns a tuple with the IpAddress field value
// and a boolean to check if the value has been set.
func (o *LoggingConfig) GetIpAddressOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.IpAddress, true
}

// SetIpAddress sets field value
func (o *LoggingConfig) SetIpAddress(v string) {
	o.IpAddress = v
}

// GetPort returns the Port field value
func (o *LoggingConfig) GetPort() int32 {
	if o == nil {
		var ret int32
		return ret
	}

	return o.Port
}

// GetPortOk returns a tuple with the Port field value
// and a boolean to check if the value has been set.
func (o *LoggingConfig) GetPortOk() (*int32, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Port, true
}

// SetPort sets field value
func (o *LoggingConfig) SetPort(v int32) {
	o.Port = v
}

// GetLogLevel returns the LogLevel field value
func (o *LoggingConfig) GetLogLevel() LogLevel {
	if o == nil {
		var ret LogLevel
		return ret
	}

	return o.LogLevel
}

// GetLogLevelOk returns a tuple with the LogLevel field value
// and a boolean to check if the value has been set.
func (o *LoggingConfig) GetLogLevelOk() (*LogLevel, bool) {
	if o == nil {
		return nil, false
	}
	return &o.LogLevel, true
}

// SetLogLevel sets field value
func (o *LoggingConfig) SetLogLevel(v LogLevel) {
	o.LogLevel = v
}

func (o LoggingConfig) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o LoggingConfig) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["ipAddress"] = o.IpAddress
	toSerialize["port"] = o.Port
	toSerialize["logLevel"] = o.LogLevel
	return toSerialize, nil
}

func (o *LoggingConfig) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"ipAddress",
		"port",
		"logLevel",
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

	varLoggingConfig := _LoggingConfig{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varLoggingConfig)

	if err != nil {
		return err
	}

	*o = LoggingConfig(varLoggingConfig)

	return err
}

type NullableLoggingConfig struct {
	value *LoggingConfig
	isSet bool
}

func (v NullableLoggingConfig) Get() *LoggingConfig {
	return v.value
}

func (v *NullableLoggingConfig) Set(val *LoggingConfig) {
	v.value = val
	v.isSet = true
}

func (v NullableLoggingConfig) IsSet() bool {
	return v.isSet
}

func (v *NullableLoggingConfig) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableLoggingConfig(val *LoggingConfig) *NullableLoggingConfig {
	return &NullableLoggingConfig{value: val, isSet: true}
}

func (v NullableLoggingConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableLoggingConfig) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


