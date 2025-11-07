package com.yash.user.exception.payload;

import org.springframework.http.HttpStatus;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;

import java.io.Serial;
import java.io.Serializable;
import java.time.ZonedDateTime;

@RequiredArgsConstructor
@AllArgsConstructor
@Data
@Builder
public class ErrorMessage implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;
    public static final String ZONED_DATE_TIME_FORMAT = "dd-MM-yyyy__HH:mm:ss:SSSSSS";

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = ZONED_DATE_TIME_FORMAT)
    private final ZonedDateTime timestamp;

    @JsonInclude(value = JsonInclude.Include.NON_NULL)
    private Throwable throwable;

    private final HttpStatus httpStatus;

    private final String msg;
}