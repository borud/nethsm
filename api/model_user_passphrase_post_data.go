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

// checks if the UserPassphrasePostData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &UserPassphrasePostData{}

// UserPassphrasePostData struct for UserPassphrasePostData
type UserPassphrasePostData struct {
	Passphrase string `json:"passphrase"`
}

type _UserPassphrasePostData UserPassphrasePostData

// NewUserPassphrasePostData instantiates a new UserPassphrasePostData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewUserPassphrasePostData(passphrase string) *UserPassphrasePostData {
	this := UserPassphrasePostData{}
	this.Passphrase = passphrase
	return &this
}

// NewUserPassphrasePostDataWithDefaults instantiates a new UserPassphrasePostData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewUserPassphrasePostDataWithDefaults() *UserPassphrasePostData {
	this := UserPassphrasePostData{}
	return &this
}

// GetPassphrase returns the Passphrase field value
func (o *UserPassphrasePostData) GetPassphrase() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Passphrase
}

// GetPassphraseOk returns a tuple with the Passphrase field value
// and a boolean to check if the value has been set.
func (o *UserPassphrasePostData) GetPassphraseOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Passphrase, true
}

// SetPassphrase sets field value
func (o *UserPassphrasePostData) SetPassphrase(v string) {
	o.Passphrase = v
}

func (o UserPassphrasePostData) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o UserPassphrasePostData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["passphrase"] = o.Passphrase
	return toSerialize, nil
}

func (o *UserPassphrasePostData) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"passphrase",
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

	varUserPassphrasePostData := _UserPassphrasePostData{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varUserPassphrasePostData)

	if err != nil {
		return err
	}

	*o = UserPassphrasePostData(varUserPassphrasePostData)

	return err
}

type NullableUserPassphrasePostData struct {
	value *UserPassphrasePostData
	isSet bool
}

func (v NullableUserPassphrasePostData) Get() *UserPassphrasePostData {
	return v.value
}

func (v *NullableUserPassphrasePostData) Set(val *UserPassphrasePostData) {
	v.value = val
	v.isSet = true
}

func (v NullableUserPassphrasePostData) IsSet() bool {
	return v.isSet
}

func (v *NullableUserPassphrasePostData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableUserPassphrasePostData(val *UserPassphrasePostData) *NullableUserPassphrasePostData {
	return &NullableUserPassphrasePostData{value: val, isSet: true}
}

func (v NullableUserPassphrasePostData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableUserPassphrasePostData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


