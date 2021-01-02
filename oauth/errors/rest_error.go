package errors

import "net/http"

const (
	// DatabaseErrorMsg string
	DatabaseErrorMsg = "database error"
)

// RestErr a unified common error struct
type RestErr struct {
	Message string `json:"message"`
	Status  int    `json:"status"`
	Error   string `json:"error"`
}

// NewBadRequestError returns a RestErr for bad request errors
func NewBadRequestError(message string) *RestErr {
	return &RestErr{
		Message: message,
		Status:  http.StatusBadRequest,
		Error:   "bad_request",
	}
}

// NewNotFoundError returns a RestErr for not found errors
func NewNotFoundError(message string) *RestErr {
	return &RestErr{
		Message: message,
		Status:  http.StatusNotFound,
		Error:   "not_found",
	}
}

// NewInternalServerError returns a RestErr for internal server error
func NewInternalServerError(message string) *RestErr {
	return &RestErr{
		Message: message,
		Status:  http.StatusInternalServerError,
		Error:   "internal_server_error",
	}
}
