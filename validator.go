package fxvalidator

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/locales/en"
	"github.com/go-playground/validator/v10"
	en_translations "github.com/go-playground/validator/v10/translations/en"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	logger "github.com/templatedop/fxlogger"
	ut "github.com/templatedop/universal-translator-master"
)

type IValidatorService interface {
	RegisterCustomValidation(tag string, fn validator.Func, message string, code string) error
	ValidateStruct(s interface{}) ([]string, []string)
	HandleValidation(ctx *gin.Context, s interface{}) bool
	HandleError(ctx *gin.Context, err error)
	HandledbError(ctx *gin.Context, err error, options ...bool)
	RegisterCustomDBError(errorMessage string, code string, httpCode int, cstmessage string) error
}

var (
	tagToNumberInstance map[string]string
	onceTagToNumber     sync.Once
	customDBErrors      = make(map[string]CustomDBError)
	customErrorCodes    = make(map[string]bool)
)

type CustomDBError struct {
	Code          string
	ErrorMessage  string
	HTTPCode      int
	CustomMessage string
}

func (vs *ValidatorService) RegisterCustomDBError(errorMessage string, code string, httpCode int, cstmessage string) error {
	if code == "" || errorMessage == "" {
		return errors.New("code and errorMessage cannot be empty")
	}

	if _, exists := customDBErrors[errorMessage]; exists {
		return fmt.Errorf("error message '%s' is already registered", errorMessage)
	}
	if _, exists := customErrorCodes[code]; exists {
		return fmt.Errorf("code '%s' is already used", code)
	}

	customErrorCodes[code] = true

	customDBErrors[errorMessage] = CustomDBError{
		ErrorMessage:  errorMessage,
		HTTPCode:      httpCode,
		Code:          code,
		CustomMessage: cstmessage,
	}

	return nil
}

func (e *CustomDBError) Error() string {
	return e.ErrorMessage
}

func GetTagToNumberMap() map[string]string {
	onceTagToNumber.Do(func() {

		tagToNumberInstance = map[string]string{
			"eqcsfield":                     "F1",
			"eqfield":                       "F2",
			"fieldcontains":                 "F3",
			"fieldexcludes":                 "F4",
			"gtcsfield":                     "F5",
			"gtecsfield":                    "F6",
			"gtefield":                      "F7",
			"gtfield":                       "F8",
			"ltcsfield":                     "F9",
			"ltecsfield":                    "F10",
			"ltefield":                      "F11",
			"ltfield":                       "F12",
			"necsfield":                     "F13",
			"nefield":                       "F14",
			"cidr":                          "N1",
			"cidrv4":                        "N2",
			"cidrv6":                        "N3",
			"datauri":                       "N4",
			"fqdn":                          "N5",
			"hostname":                      "N6",
			"hostname_port":                 "N7",
			"hostname_rfc1123":              "N8",
			"ip":                            "N9",
			"ip4_addr":                      "N10",
			"ip6_addr":                      "N11",
			"ip_addr":                       "N12",
			"ipv4":                          "N13",
			"ipv6":                          "N14",
			"mac":                           "N15",
			"tcp4_addr":                     "N16",
			"tcp6_addr":                     "N17",
			"tcp_addr":                      "N18",
			"udp4_addr":                     "N19",
			"udp6_addr":                     "N20",
			"udp_addr":                      "N21",
			"unix_addr":                     "N22",
			"uri":                           "N23",
			"url":                           "N24",
			"http_url":                      "N25",
			"url_encoded":                   "N26",
			"urn_rfc2141":                   "N27",
			"alpha":                         "S1",
			"alphanum":                      "S2",
			"alphanumunicode":               "S3",
			"alphaunicode":                  "S4",
			"ascii":                         "S5",
			"boolean":                       "S6",
			"contains":                      "S7",
			"containsany":                   "S8",
			"containsrune":                  "S9",
			"endsnotwith":                   "S10",
			"endswith":                      "S11",
			"excludes":                      "S12",
			"excludesall":                   "S13",
			"excludesrune":                  "S14",
			"lowercase":                     "S15",
			"multibyte":                     "S16",
			"number":                        "S17",
			"numeric":                       "S18",
			"printascii":                    "S19",
			"startsnotwith":                 "S20",
			"startswith":                    "S21",
			"uppercase":                     "S22",
			"base64":                        "FMT1",
			"base64url":                     "FMT2",
			"base64rawurl":                  "FMT3",
			"bic":                           "FMT4",
			"bcp47_language_tag":            "FMT5",
			"btc_addr":                      "FMT6",
			"btc_addr_bech32":               "FMT7",
			"credit_card":                   "FMT8",
			"mongodb":                       "FMT9",
			"cron":                          "FMT10",
			"spicedb":                       "FMT11",
			"datetime":                      "FMT12",
			"e164":                          "FMT13",
			"email":                         "FMT14",
			"eth_addr":                      "FMT15",
			"hexadecimal":                   "FMT16",
			"hexcolor":                      "FMT17",
			"hsl":                           "FMT18",
			"hsla":                          "FMT19",
			"html":                          "FMT20",
			"html_encoded":                  "FMT21",
			"isbn":                          "FMT22",
			"isbn10":                        "FMT23",
			"isbn13":                        "FMT24",
			"issn":                          "FMT25",
			"iso3166_1_alpha2":              "FMT26",
			"iso3166_1_alpha3":              "FMT27",
			"iso3166_1_alpha_numeric":       "FMT28",
			"iso3166_2":                     "FMT29",
			"iso4217":                       "FMT30",
			"json":                          "FMT31",
			"jwt":                           "FMT32",
			"latitude":                      "FMT33",
			"longitude":                     "FMT34",
			"luhn_checksum":                 "FMT35",
			"postcode_iso3166_alpha2":       "FMT36",
			"postcode_iso3166_alpha2_field": "FMT37",
			"rgb":                           "FMT38",
			"rgba":                          "FMT39",
			"ssn":                           "FMT40",
			"timezone":                      "FMT41",
			"uuid":                          "FMT42",
			"uuid3":                         "FMT43",
			"uuid3_rfc4122":                 "FMT44",
			"uuid4":                         "FMT45",
			"uuid4_rfc4122":                 "FMT46",
			"uuid5":                         "FMT47",
			"uuid5_rfc4122":                 "FMT48",
			"uuid_rfc4122":                  "FMT49",
			"md4":                           "FMT50",
			"md5":                           "FMT51",
			"sha256":                        "FMT52",
			"sha384":                        "FMT53",
			"sha512":                        "FMT54",
			"ripemd128":                     "FMT55",

			"tiger128":             "FMT57",
			"tiger160":             "FMT58",
			"tiger192":             "FMT59",
			"semver":               "FMT60",
			"ulid":                 "FMT61",
			"cve":                  "FMT62",
			"eq":                   "C1",
			"eq_ignore_case":       "C2",
			"gt":                   "C3",
			"gte":                  "C4",
			"lt":                   "C5",
			"lte":                  "C6",
			"ne":                   "C7",
			"ne_ignore_case":       "C8",
			"dir":                  "O1",
			"dirpath":              "O2",
			"file":                 "O3",
			"filepath":             "O4",
			"image":                "O5",
			"isdefault":            "O6",
			"len":                  "O7",
			"max":                  "O8",
			"min":                  "O9",
			"oneof":                "O10",
			"required":             "O11",
			"required_if":          "O12",
			"required_unless":      "O13",
			"required_with":        "O14",
			"required_with_all":    "O15",
			"required_without":     "O16",
			"required_without_all": "O17",
			"excluded_if":          "O18",
			"excluded_unless":      "O19",
			"excluded_with":        "O20",
			"excluded_with_all":    "O21",
			"excluded_without":     "O22",
			"excluded_without_all": "O23",
			"unique":               "O24",
			"iscolor":              "A1",
			"country_code":         "A2",
		}

	})
	return tagToNumberInstance
}

type CustomValidation struct {
	Tag     string
	Func    validator.Func
	Message string
	Code    string
}

type ValidatorService struct {
	validate          *validator.Validate
	trans             ut.Translator
	customValidations map[string]CustomValidation
	tagToNumber       map[string]string
	log               *logger.Logger
	customdberror     map[string]CustomDBError
}

// func NewValidatorService(tagToNumber map[string]string, errordbMap map[string]string) (*ValidatorService, error) {
func NewValidatorService(tagToNumber map[string]string, log *logger.Logger) (IValidatorService, error) {
	en := en.New()
	uni := ut.New(en, en)
	trans, _ := uni.GetTranslator("en")
	validate := validator.New()

	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})

	err := en_translations.RegisterDefaultTranslations(validate, trans)
	if err != nil {
		return nil, err
	}

	return &ValidatorService{
		validate:          validate,
		trans:             trans,
		customValidations: make(map[string]CustomValidation),
		tagToNumber:       tagToNumber,
		log:               log,
		customdberror:     make(map[string]CustomDBError),
	}, nil
}

func (vs *ValidatorService) RegisterCustomValidation(tag string, fn validator.Func, message string, code string) error {
	if tag == "" {
		return errors.New("validation tag cannot be empty")
	}
	if fn == nil {
		return errors.New("validation function cannot be nil")
	}

	if _, exists := vs.customValidations[tag]; exists {
		return fmt.Errorf("validation tag '%s' is already registered", tag)
	}

	err := vs.validate.RegisterValidation(tag, fn)
	if err != nil {
		return fmt.Errorf("failed to register validation for tag '%s': %v", tag, err)
	}
	vs.customValidations[tag] = CustomValidation{Tag: tag, Func: fn, Message: message, Code: code}
	return nil
}

func (vs *ValidatorService) ValidateStruct(s interface{}) ([]string, []string) {
	var errorMessages []string
	var errorNumbers []string

	err := vs.validate.Struct(s)
	if err != nil {
		validationErrors := err.(validator.ValidationErrors)
		for _, e := range validationErrors {

			fieldName := e.StructField()
			structField, _ := reflect.TypeOf(s).FieldByName(fieldName)
			tag := e.Tag()
			if cv, ok := vs.customValidations[tag]; ok {
				errorMessages = append(errorMessages, e.Field()+" "+cv.Message)
				errorNumbers = append(errorNumbers, cv.Code)
			} else {

				errorMessages = append(errorMessages, e.Translate(vs.trans))
				userDefinedValue := structField.Tag.Get("u")
				errorNumbers = append(errorNumbers, vs.tagToNumber[e.Tag()]+userDefinedValue)
			}
		}
		return errorMessages, errorNumbers
	}
	return nil, nil
}

// errorValidResponse represents a JSON response for validation errors.
type errorValidResponse struct {
	Success bool     `json:"success" example:"false"`
	Message []string `json:"message" example:"Error message"`
	Errorno []string `json:"errorno"`
}

// newErrorValidResponse creates a new error response body.
func newErrorValidResponse(message []string, errorno []string) errorValidResponse {
	return errorValidResponse{
		Success: false,
		Message: message,
		Errorno: errorno,
	}
}

func (vs *ValidatorService) HandleValidation(ctx *gin.Context, s interface{}) bool {
	errorMessages, errorNumbers := vs.ValidateStruct(s)
	if len(errorMessages) > 0 {

		errRsp := newErrorValidResponse(errorMessages, errorNumbers)
		ctx.JSON(http.StatusBadRequest, errRsp)
		return false
	}
	return true
}

var (
	ErrInvalidArgument = errors.New("invalid argument")
	ErrNotFound        = errors.New("not found")
	// ErrDataNotFound is an error for when requested data is not found
	ErrDataNotFound = errors.New("data not found")
	// ErrNoUpdatedData is an error for when no data is provided to update
	ErrNoUpdatedData = errors.New("no data to update")
	// ErrConflictingData is an error for when data conflicts with existing data
	ErrConflictingData = errors.New("data conflicts with existing data in unique column")
	// ErrInsufficientStock is an error for when product stock is not enough
	ErrInsufficientStock = errors.New("product stock is not enough")
	// ErrInsufficientPayment is an error for when total paid is less than total price
	ErrInsufficientPayment = errors.New("total paid is less than total price")
	// ErrExpiredToken is an error for when the access token is expired
	ErrExpiredToken = errors.New("access token has expired")
	// ErrInvalidToken is an error for when the access token is invalid
	ErrInvalidToken = errors.New("access token is invalid")
	// ErrInvalidCredentials is an error for when the credentials are invalid
	ErrInvalidCredentials = errors.New("invalid email or password")
	// ErrEmptyAuthorizationHeader is an error for when the authorization header is empty
	ErrEmptyAuthorizationHeader = errors.New("authorization header is not provided")
	// ErrInvalidAuthorizationHeader is an error for when the authorization header is invalid
	ErrInvalidAuthorizationHeader = errors.New("authorization header format is invalid")
	// ErrInvalidAuthorizationType is an error for when the authorization type is invalid
	ErrInvalidAuthorizationType = errors.New("authorization type is not supported")
	// ErrUnauthorized is an error for when the user is unauthorized
	ErrUnauthorized = errors.New("user is unauthorized to access the resource")
	// ErrForbidden is an error for when the user is forbidden to access the resource
	ErrForbidden = errors.New("user is forbidden to access the resource")
)

var errorStatusMap = map[error]int{
	ErrDataNotFound:               http.StatusNotFound,
	ErrConflictingData:            http.StatusConflict,
	ErrInvalidCredentials:         http.StatusUnauthorized,
	ErrUnauthorized:               http.StatusUnauthorized,
	ErrEmptyAuthorizationHeader:   http.StatusUnauthorized,
	ErrInvalidAuthorizationHeader: http.StatusUnauthorized,
	ErrInvalidAuthorizationType:   http.StatusUnauthorized,
	ErrInvalidToken:               http.StatusUnauthorized,
	ErrExpiredToken:               http.StatusUnauthorized,
	ErrForbidden:                  http.StatusForbidden,
	ErrNoUpdatedData:              http.StatusBadRequest,
	ErrInsufficientStock:          http.StatusBadRequest,
	ErrInsufficientPayment:        http.StatusBadRequest,
}

func (vs *ValidatorService) HandleError(ctx *gin.Context, err error) {
	var errormsg string
	statusCode, ok := errorStatusMap[err]
	if !ok {
		re := regexp.MustCompile(`cannot unmarshal (.*?) into Go struct field (.*?) of type (.*)$`)
		matches := re.FindStringSubmatch(err.Error())
		re1 := regexp.MustCompile(`invalid character '(.+?)'`)
		matches1 := re1.FindStringSubmatch(err.Error())
		if len(matches) == 4 {
			expectedType := matches[3]
			fieldarray := strings.Split(matches[2], ".")
			fieldvalue := fieldarray[1]
			errormsg = "Send " + expectedType + " for field: " + fieldvalue
		} else if len(matches1) == 2 {
			errormsg = "Malformed json request"
		} else {

			errormsg = err.Error()
		}
		statusCode = http.StatusUnprocessableEntity
	}

	var errRsp errorValidResponse
	var errorMessages []string
	var erronumbers []string
	erronumbers = append(erronumbers, "UP1")
	if errormsg == "" {
		errorMessages = append(errorMessages, err.Error())
		errRsp = newErrorValidResponse(errorMessages, erronumbers)
	} else {
		//errormsgs:= newErrorResponse(errormsg)
		errorMessages = append(errorMessages, errormsg)
		errRsp = newErrorValidResponse(errorMessages, erronumbers)
	}

	ctx.JSON(statusCode, errRsp)
}

func finddberror(err error, singleresource bool) CustomDBError {
	if customErr, exists := customDBErrors[err.Error()]; exists {

		if singleresource && err.Error() == "no rows in result set" {
			customErr.HTTPCode = http.StatusNotFound
			customErr.CustomMessage = "No data found"
		}
		return customErr
	}
	return CustomDBError{}
}
func (vs *ValidatorService) HandledbError(ctx *gin.Context, err error, options ...bool) {
	statusCode := 500

	pgErr, ok := err.(*pgconn.PgError)
	if !ok {
		var er CustomDBError
		if len(options) > 0 {
			er = finddberror(err, options[0])

		} else {
			er = finddberror(err, false)

		}

		if er.ErrorMessage != "" {
			vs.log.Error("Error in db:", err.Error())
			ctx.JSON(er.HTTPCode, newErrordbResponse([]string{er.CustomMessage}, []string{er.Code}))
			return
		} else {
			vs.log.Error("Error in db:", err.Error())
			ctx.JSON(statusCode, newErrordbResponse([]string{"Unknown DB Error"}, []string{"PGO46"}))
			return
		}

	}
	sqlState := pgErr.Code
	switch {

	case pgerrcode.IsCardinalityViolation(sqlState):
		errRsps := newErrordbResponse([]string{"Cardinality violation"}, []string{"PG01"})
		ctx.JSON(http.StatusBadRequest, errRsps)
		return

	case pgerrcode.IsWarning(sqlState):
		errRsps := newErrordbResponse([]string{"Warning"}, []string{"PG02"})
		ctx.JSON(http.StatusOK, errRsps)
		return
	case pgerrcode.IsNoData(sqlState):
		errRsps := newErrordbResponse([]string{"No data found"}, []string{"PG03"})
		ctx.JSON(http.StatusNotFound, errRsps)
		return
	case pgerrcode.IsSQLStatementNotYetComplete(sqlState):
		errRsps := newErrordbResponse([]string{"SQL statement not yet complete"}, []string{"PG04"})
		ctx.JSON(http.StatusUnprocessableEntity, errRsps)
		return
	case pgerrcode.IsConnectionException(sqlState):
		errRsps := newErrordbResponse([]string{"Connection exception"}, []string{"PG05"})
		ctx.JSON(http.StatusServiceUnavailable, errRsps)
		return
	case pgerrcode.IsTriggeredActionException(sqlState):
		errRsps := newErrordbResponse([]string{"Triggered action exception"}, []string{"PG06"})
		ctx.JSON(http.StatusUnprocessableEntity, errRsps)
		return
	case pgerrcode.IsFeatureNotSupported(sqlState):
		errRsps := newErrordbResponse([]string{"Feature not supported"}, []string{"PG07"})
		ctx.JSON(http.StatusNotImplemented, errRsps)
		return
	case pgerrcode.IsInvalidTransactionInitiation(sqlState):
		errRsps := newErrordbResponse([]string{"Invalid transaction initiation"}, []string{"PG08"})
		ctx.JSON(http.StatusUnprocessableEntity, errRsps)
		return
	case pgerrcode.IsLocatorException(sqlState):
		errRsps := newErrordbResponse([]string{"Locator exception"}, []string{"PG09"})
		ctx.JSON(http.StatusUnprocessableEntity, errRsps)
		return
	case pgerrcode.IsInvalidGrantor(sqlState):
		errRsps := newErrordbResponse([]string{"Invalid grantor"}, []string{"PG10"})
		ctx.JSON(http.StatusUnprocessableEntity, errRsps)
		return
	case pgerrcode.IsInvalidRoleSpecification(sqlState):
		errRsps := newErrordbResponse([]string{"Invalid role specification"}, []string{"PG11"})
		ctx.JSON(http.StatusUnprocessableEntity, errRsps)
		return
	case pgerrcode.IsDiagnosticsException(sqlState):
		errRsps := newErrordbResponse([]string{"Diagnostics exception"}, []string{"PG12"})
		ctx.JSON(http.StatusUnprocessableEntity, errRsps)
		return
	case pgerrcode.IsCaseNotFound(sqlState):
		errRsps := newErrordbResponse([]string{"Case not found"}, []string{"PG13"})
		ctx.JSON(http.StatusNotFound, errRsps)
		return
	case pgerrcode.IsCardinalityViolation(sqlState):
		errRsps := newErrordbResponse([]string{"Cardinality violation"}, []string{"PG14"})
		ctx.JSON(http.StatusBadRequest, errRsps)
		return
	case pgerrcode.IsDataException(sqlState):
		errRsps := newErrordbResponse([]string{"Data exception"}, []string{"PG15"})
		ctx.JSON(http.StatusUnprocessableEntity, errRsps)
		return
	case pgerrcode.IsIntegrityConstraintViolation(sqlState):
		errRsps := newErrordbResponse([]string{"Integrity constraint violation"}, []string{"PG16"})
		ctx.JSON(http.StatusConflict, errRsps)
		return
	case pgerrcode.IsInvalidCursorState(sqlState):
		errRsps := newErrordbResponse([]string{"Invalid cursor state"}, []string{"PG17"})
		ctx.JSON(http.StatusUnprocessableEntity, errRsps)
		return
	case pgerrcode.IsInvalidTransactionState(sqlState):
		errRsps := newErrordbResponse([]string{"Invalid transaction state"}, []string{"PG18"})
		ctx.JSON(http.StatusConflict, errRsps)
		return
	case pgerrcode.IsInvalidSQLStatementName(sqlState):
		errRsps := newErrordbResponse([]string{"Invalid SQL statement name"}, []string{"PG19"})
		ctx.JSON(http.StatusUnprocessableEntity, errRsps)
		return
	case pgerrcode.IsTriggeredDataChangeViolation(sqlState):
		errRsps := newErrordbResponse([]string{"Triggered data change violation"}, []string{"PG20"})
		ctx.JSON(http.StatusUnprocessableEntity, errRsps)
		return
	case pgerrcode.IsInvalidAuthorizationSpecification(sqlState):
		errRsps := newErrordbResponse([]string{"Invalid authorization specification"}, []string{"PG21"})
		ctx.JSON(http.StatusUnauthorized, errRsps)
		return
	case pgerrcode.IsDependentPrivilegeDescriptorsStillExist(sqlState):
		errRsps := newErrordbResponse([]string{"Dependent privilege descriptors still exist"}, []string{"PG22"})
		ctx.JSON(http.StatusUnprocessableEntity, errRsps)
		return
	case pgerrcode.IsInvalidTransactionTermination(sqlState):
		errRsps := newErrordbResponse([]string{"Invalid transaction termination"}, []string{"PG23"})
		ctx.JSON(http.StatusUnprocessableEntity, errRsps)
		return
	case pgerrcode.IsSQLRoutineException(sqlState):
		errRsps := newErrordbResponse([]string{"SQL routine exception"}, []string{"PG24"})
		ctx.JSON(http.StatusInternalServerError, errRsps)
		return
	case pgerrcode.IsInvalidCursorName(sqlState):
		errRsps := newErrordbResponse([]string{"Invalid cursor name"}, []string{"PG25"})
		ctx.JSON(http.StatusInternalServerError, errRsps)
		return
	case pgerrcode.IsExternalRoutineException(sqlState):
		errRsps := newErrordbResponse([]string{"External routine exception"}, []string{"PG26"})
		ctx.JSON(http.StatusInternalServerError, errRsps)
		return
	case pgerrcode.IsExternalRoutineInvocationException(sqlState):
		errRsps := newErrordbResponse([]string{"External routine invocation exception"}, []string{"PG27"})
		ctx.JSON(http.StatusUnprocessableEntity, errRsps)
		return
	case pgerrcode.IsSavepointException(sqlState):
		errRsps := newErrordbResponse([]string{"Savepoint exception"}, []string{"PG28"})
		ctx.JSON(http.StatusUnprocessableEntity, errRsps)
		return
	case pgerrcode.IsInvalidCatalogName(sqlState):
		errRsps := newErrordbResponse([]string{"Invalid catalog name"}, []string{"PG29"})
		ctx.JSON(http.StatusUnprocessableEntity, errRsps)
		return
	case pgerrcode.IsInvalidSchemaName(sqlState):
		errRsps := newErrordbResponse([]string{"Invalid schema name"}, []string{"PG30"})
		ctx.JSON(http.StatusUnprocessableEntity, errRsps)
		return
	case pgerrcode.IsTransactionRollback(sqlState):
		errRsps := newErrordbResponse([]string{"Transaction rollback"}, []string{"PG31"})
		ctx.JSON(http.StatusConflict, errRsps)
		return
	case pgerrcode.IsSyntaxErrororAccessRuleViolation(sqlState):
		errRsps := newErrordbResponse([]string{"Syntax error or access rule violation"}, []string{"PG32"})
		ctx.JSON(http.StatusBadRequest, errRsps)
		return
	case pgerrcode.IsWithCheckOptionViolation(sqlState):
		errRsps := newErrordbResponse([]string{"With check option violation"}, []string{"PG33"})
		ctx.JSON(http.StatusConflict, errRsps)
		return
	case pgerrcode.IsInsufficientResources(sqlState):
		errRsps := newErrordbResponse([]string{"Insufficient resources"}, []string{"PG34"})
		ctx.JSON(http.StatusServiceUnavailable, errRsps)
		return
	case pgerrcode.IsProgramLimitExceeded(sqlState):
		errRsps := newErrordbResponse([]string{"Program limit exceeded"}, []string{"PG35"})
		ctx.JSON(http.StatusServiceUnavailable, errRsps)
		return
	case pgerrcode.IsObjectNotInPrerequisiteState(sqlState):
		errRsps := newErrordbResponse([]string{"Object not in prerequisite state"}, []string{"PG36"})
		ctx.JSON(http.StatusUnprocessableEntity, errRsps)
		return
	case pgerrcode.IsOperatorIntervention(sqlState):
		errRsps := newErrordbResponse([]string{"Operator intervention"}, []string{"PG37"})
		ctx.JSON(http.StatusServiceUnavailable, errRsps)
		return
	case pgerrcode.IsSystemError(sqlState):
		errRsps := newErrordbResponse([]string{"System error"}, []string{"PG38"})
		ctx.JSON(http.StatusInternalServerError, errRsps)
		return
	case pgerrcode.IsSnapshotFailure(sqlState):
		errRsps := newErrordbResponse([]string{"Snapshot failure"}, []string{"PG39"})
		ctx.JSON(http.StatusConflict, errRsps)
		return
	case pgerrcode.IsConfigurationFileError(sqlState):
		errRsps := newErrordbResponse([]string{"Configuration file error"}, []string{"PG40"})
		ctx.JSON(http.StatusInternalServerError, errRsps)
		return
	case pgerrcode.IsForeignDataWrapperError(sqlState):
		errRsps := newErrordbResponse([]string{"Foreign data wrapper error"}, []string{"PG41"})
		ctx.JSON(http.StatusInternalServerError, errRsps)
		return
	case pgerrcode.IsPLpgSQLError(sqlState):
		errRsps := newErrordbResponse([]string{"PL/pgSQL error"}, []string{"PG42"})
		ctx.JSON(http.StatusInternalServerError, errRsps)
		return
	default:
		errRsps := newErrordbResponse([]string{"Unknown database error"}, []string{"PG43"})
		ctx.JSON(http.StatusInternalServerError, errRsps)
		return

	}

}

type errordbResponse struct {
	Success bool     `json:"success" example:"false"`
	Message []string `json:"message" example:"Error message"`
	Errorno []string `json:"errorno"`
}

// newErrorResponse is a helper function to create an error response body
func newErrordbResponse(message []string, errorno []string) errordbResponse {

	return errordbResponse{
		Success: false,
		Message: message,
		Errorno: errorno,
	}
}
