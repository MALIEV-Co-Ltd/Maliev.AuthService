using System;

namespace Maliev.AuthService.Common.Exceptions
{
    /// <summary>
    /// Represents an exception that occurs when external service validation fails.
    /// </summary>
    public class ExternalServiceValidationException : Exception
    {
        /// <summary>
        /// Gets the HTTP status code returned by the external service.
        /// </summary>
        public int? StatusCode { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="ExternalServiceValidationException"/> class.
        /// </summary>
        public ExternalServiceValidationException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ExternalServiceValidationException"/> class with a specified error message.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public ExternalServiceValidationException(string message) : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ExternalServiceValidationException"/> class with a specified error message and HTTP status code.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="statusCode">The HTTP status code returned by the external service.</param>
        public ExternalServiceValidationException(string message, int statusCode) : base(message)
        {
            StatusCode = statusCode;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ExternalServiceValidationException"/> class with a specified error message and a reference to the inner exception that is the cause of this exception.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="innerException">The exception that is the cause of the current exception, or a null reference if no inner exception is specified.</param>
        public ExternalServiceValidationException(string message, Exception innerException) : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ExternalServiceValidationException"/> class with a specified error message, HTTP status code, and a reference to the inner exception that is the cause of this exception.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="statusCode">The HTTP status code returned by the external service.</param>
        /// <param name="innerException">The exception that is the cause of the current exception, or a null reference if no inner exception is specified.</param>
        public ExternalServiceValidationException(string message, int statusCode, Exception innerException) : base(message, innerException)
        {
            StatusCode = statusCode;
        }
    }
}