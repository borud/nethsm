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

// checks if the BackupPassphraseConfig type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &BackupPassphraseConfig{}

// BackupPassphraseConfig struct for BackupPassphraseConfig
type BackupPassphraseConfig struct {
	NewPassphrase string `json:"newPassphrase"`
	CurrentPassphrase string `json:"currentPassphrase"`
}

type _BackupPassphraseConfig BackupPassphraseConfig

// NewBackupPassphraseConfig instantiates a new BackupPassphraseConfig object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewBackupPassphraseConfig(newPassphrase string, currentPassphrase string) *BackupPassphraseConfig {
	this := BackupPassphraseConfig{}
	this.NewPassphrase = newPassphrase
	this.CurrentPassphrase = currentPassphrase
	return &this
}

// NewBackupPassphraseConfigWithDefaults instantiates a new BackupPassphraseConfig object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewBackupPassphraseConfigWithDefaults() *BackupPassphraseConfig {
	this := BackupPassphraseConfig{}
	return &this
}

// GetNewPassphrase returns the NewPassphrase field value
func (o *BackupPassphraseConfig) GetNewPassphrase() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.NewPassphrase
}

// GetNewPassphraseOk returns a tuple with the NewPassphrase field value
// and a boolean to check if the value has been set.
func (o *BackupPassphraseConfig) GetNewPassphraseOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.NewPassphrase, true
}

// SetNewPassphrase sets field value
func (o *BackupPassphraseConfig) SetNewPassphrase(v string) {
	o.NewPassphrase = v
}

// GetCurrentPassphrase returns the CurrentPassphrase field value
func (o *BackupPassphraseConfig) GetCurrentPassphrase() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.CurrentPassphrase
}

// GetCurrentPassphraseOk returns a tuple with the CurrentPassphrase field value
// and a boolean to check if the value has been set.
func (o *BackupPassphraseConfig) GetCurrentPassphraseOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.CurrentPassphrase, true
}

// SetCurrentPassphrase sets field value
func (o *BackupPassphraseConfig) SetCurrentPassphrase(v string) {
	o.CurrentPassphrase = v
}

func (o BackupPassphraseConfig) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o BackupPassphraseConfig) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["newPassphrase"] = o.NewPassphrase
	toSerialize["currentPassphrase"] = o.CurrentPassphrase
	return toSerialize, nil
}

func (o *BackupPassphraseConfig) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"newPassphrase",
		"currentPassphrase",
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

	varBackupPassphraseConfig := _BackupPassphraseConfig{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varBackupPassphraseConfig)

	if err != nil {
		return err
	}

	*o = BackupPassphraseConfig(varBackupPassphraseConfig)

	return err
}

type NullableBackupPassphraseConfig struct {
	value *BackupPassphraseConfig
	isSet bool
}

func (v NullableBackupPassphraseConfig) Get() *BackupPassphraseConfig {
	return v.value
}

func (v *NullableBackupPassphraseConfig) Set(val *BackupPassphraseConfig) {
	v.value = val
	v.isSet = true
}

func (v NullableBackupPassphraseConfig) IsSet() bool {
	return v.isSet
}

func (v *NullableBackupPassphraseConfig) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableBackupPassphraseConfig(val *BackupPassphraseConfig) *NullableBackupPassphraseConfig {
	return &NullableBackupPassphraseConfig{value: val, isSet: true}
}

func (v NullableBackupPassphraseConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableBackupPassphraseConfig) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


