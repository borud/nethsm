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

// checks if the EncryptData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &EncryptData{}

// EncryptData struct for EncryptData
type EncryptData struct {
	Encrypted string `json:"encrypted" validate:"regexp=^[a-zA-Z0-9+\\/]+={0,3}$"`
	Iv string `json:"iv" validate:"regexp=^[a-zA-Z0-9+\\/]+={0,3}$"`
}

type _EncryptData EncryptData

// NewEncryptData instantiates a new EncryptData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewEncryptData(encrypted string, iv string) *EncryptData {
	this := EncryptData{}
	this.Encrypted = encrypted
	this.Iv = iv
	return &this
}

// NewEncryptDataWithDefaults instantiates a new EncryptData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewEncryptDataWithDefaults() *EncryptData {
	this := EncryptData{}
	return &this
}

// GetEncrypted returns the Encrypted field value
func (o *EncryptData) GetEncrypted() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Encrypted
}

// GetEncryptedOk returns a tuple with the Encrypted field value
// and a boolean to check if the value has been set.
func (o *EncryptData) GetEncryptedOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Encrypted, true
}

// SetEncrypted sets field value
func (o *EncryptData) SetEncrypted(v string) {
	o.Encrypted = v
}

// GetIv returns the Iv field value
func (o *EncryptData) GetIv() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Iv
}

// GetIvOk returns a tuple with the Iv field value
// and a boolean to check if the value has been set.
func (o *EncryptData) GetIvOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Iv, true
}

// SetIv sets field value
func (o *EncryptData) SetIv(v string) {
	o.Iv = v
}

func (o EncryptData) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o EncryptData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["encrypted"] = o.Encrypted
	toSerialize["iv"] = o.Iv
	return toSerialize, nil
}

func (o *EncryptData) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"encrypted",
		"iv",
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

	varEncryptData := _EncryptData{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varEncryptData)

	if err != nil {
		return err
	}

	*o = EncryptData(varEncryptData)

	return err
}

type NullableEncryptData struct {
	value *EncryptData
	isSet bool
}

func (v NullableEncryptData) Get() *EncryptData {
	return v.value
}

func (v *NullableEncryptData) Set(val *EncryptData) {
	v.value = val
	v.isSet = true
}

func (v NullableEncryptData) IsSet() bool {
	return v.isSet
}

func (v *NullableEncryptData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableEncryptData(val *EncryptData) *NullableEncryptData {
	return &NullableEncryptData{value: val, isSet: true}
}

func (v NullableEncryptData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableEncryptData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


