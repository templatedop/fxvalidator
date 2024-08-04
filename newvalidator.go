package fxvalidator

import logger "github.com/templatedop/fxlogger"

func NewValidService(log *logger.Logger) (IValidatorService, error) {
	tagToNumber := GetTagToNumberMap()
	var err error
	validatorService, err := NewValidatorService(tagToNumber, log)
	if err != nil {
		return nil, err
	}
	return validatorService, nil
}
