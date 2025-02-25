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

// checks if the SignData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &SignData{}

// SignData struct for SignData
type SignData struct {
	Signature string `json:"signature" validate:"regexp=^[a-zA-Z0-9+\\/]+={0,3}$"`
}

type _SignData SignData

// NewSignData instantiates a new SignData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewSignData(signature string) *SignData {
	this := SignData{}
	this.Signature = signature
	return &this
}

// NewSignDataWithDefaults instantiates a new SignData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewSignDataWithDefaults() *SignData {
	this := SignData{}
	return &this
}

// GetSignature returns the Signature field value
func (o *SignData) GetSignature() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Signature
}

// GetSignatureOk returns a tuple with the Signature field value
// and a boolean to check if the value has been set.
func (o *SignData) GetSignatureOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Signature, true
}

// SetSignature sets field value
func (o *SignData) SetSignature(v string) {
	o.Signature = v
}

func (o SignData) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o SignData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["signature"] = o.Signature
	return toSerialize, nil
}

func (o *SignData) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"signature",
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

	varSignData := _SignData{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varSignData)

	if err != nil {
		return err
	}

	*o = SignData(varSignData)

	return err
}

type NullableSignData struct {
	value *SignData
	isSet bool
}

func (v NullableSignData) Get() *SignData {
	return v.value
}

func (v *NullableSignData) Set(val *SignData) {
	v.value = val
	v.isSet = true
}

func (v NullableSignData) IsSet() bool {
	return v.isSet
}

func (v *NullableSignData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableSignData(val *SignData) *NullableSignData {
	return &NullableSignData{value: val, isSet: true}
}

func (v NullableSignData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableSignData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


