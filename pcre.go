// Copyright (c) 2011 Florian Weimer. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Package pcre2 provides access to version 2 of the Perl Compatible Regular
// Expresion library, PCRE.
//
// It implements two main types, Regexp and Matcher.  Regexp objects
// store a compiled regular expression. They consist of two immutable
// parts: pcre and pcre_extra. Compile()/MustCompile() initialize pcre.
// Calling Study() on a compiled Regexp initializes pcre_extra.
// Compilation of regular expressions using Compile or MustCompile is
// slightly expensive, so these objects should be kept and reused,
// instead of compiling them from scratch for each matching attempt.
// CompileJIT and MustCompileJIT are way more expensive, because they
// run Study() after compiling a Regexp, but they tend to give
// much better performance:
// http://sljit.sourceforge.net/regex_perf.html
//
// Matcher objects keeps the results of a match against a []byte or
// string subject.  The Group and GroupString functions provide access
// to capture groups; both versions work no matter if the subject was a
// []byte or string, but the version with the matching type is slightly
// more efficient.
//
// Matcher objects contain some temporary space and refer the original
// subject.  They are mutable and can be reused (using Match,
// MatchString, Reset or ResetString).
//
// For details on the regular expression language implemented by this
// package and the flags defined below, see the PCRE documentation.
// http://www.pcre.org/pcre2.txt
package pcre2

/*
#cgo pkg-config: libpcre2-8
#define PCRE2_CODE_UNIT_WIDTH 8

#include <pcre2.h>
#include <string.h>

#define MY_PCRE2_ERROR_MESSAGE_BUF_LEN 256
static void * MY_pcre2_get_error_message(int errnum) {
	PCRE2_UCHAR *buf = (PCRE2_UCHAR *) malloc(sizeof(PCRE2_UCHAR) * MY_PCRE2_ERROR_MESSAGE_BUF_LEN);
	pcre2_get_error_message(errnum, buf, MY_PCRE2_ERROR_MESSAGE_BUF_LEN);
	return buf;
}
#include "./pcre2_fallback.h"

#define MY_STATIC_MATCH_DATA_SIZE offsetof(pcre2_match_data, ovector)
#define MY_PCRE2_SIZE
#define MY_CONTEXT_SIZE sizeof(pcre2_general_context)

uint32_t myGetStaticMatchDataSize() {
	pcre2_match_data * md = pcre2_match_data_create(0, NULL);
	PCRE2_SIZE* ovector = pcre2_get_ovector_pointer(md);
	uint32_t result = ((void*) ovector) - ((void*) md);
	pcre2_match_data_free(md);
	return result;
}
uint32_t myGetContextSize() {
	pcre2_general_context * c = pcre2_general_context_create(NULL, NULL, NULL);
	uint32_t result = sizeof(c);
	pcre2_general_context_free(c);
	return result;
}
uint32_t myStaticMatchDataSize;
uint32_t myPcre2Size = sizeof(PCRE2_SIZE);
uint32_t myContextSize;
void myInitSizes() {
	myStaticMatchDataSize = myGetStaticMatchDataSize();
	myContextSize = myGetContextSize();
}
*/
import "C"

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"sync"
	"unsafe"
)

const myErrorMessageBufLen = C.MY_PCRE2_ERROR_MESSAGE_BUF_LEN

// The following option bits can be passed to Compile(), Match(),
// or DfaMatch(). NO_UTF_CHECK affects only the function to which it
// is passed. Put these bits at the most significant end of the options word so
// others can be added next to them.
const (
	ANCHORED     = C.PCRE2_ANCHORED
	NO_UTF_CHECK = C.PCRE2_NO_UTF_CHECK
	ENDANCHORED  = C.PCRE2_ENDANCHORED
)

// The following option bits can be passed only to Compile(). However,
// they may affect compilation, JIT compilation, and/or interpretive execution.
// The following tags indicate which:
//
// C   alters what is compiled by pcre2_compile()
// J   alters what is compiled by pcre2_jit_compile()
// M   is inspected during pcre2_match() execution
// D   is inspected during pcre2_dfa_match() execution
const (
	ALLOW_EMPTY_CLASS   = C.PCRE2_ALLOW_EMPTY_CLASS   /* C       */
	ALT_BSUX            = C.PCRE2_ALT_BSUX            /* C       */
	AUTO_CALLOUT        = C.PCRE2_AUTO_CALLOUT        /* C       */
	CASELESS            = C.PCRE2_CASELESS            /* C       */
	DOLLAR_ENDONLY      = C.PCRE2_DOLLAR_ENDONLY      /*   J M D */
	DOTALL              = C.PCRE2_DOTALL              /* C       */
	DUPNAMES            = C.PCRE2_DUPNAMES            /* C       */
	EXTENDED            = C.PCRE2_EXTENDED            /* C       */
	FIRSTLINE           = C.PCRE2_FIRSTLINE           /*   J M D */
	MATCH_UNSET_BACKREF = C.PCRE2_MATCH_UNSET_BACKREF /* C J M   */
	MULTILINE           = C.PCRE2_MULTILINE           /* C       */
	NEVER_UCP           = C.PCRE2_NEVER_UCP           /* C       */
	NEVER_UTF           = C.PCRE2_NEVER_UTF           /* C       */
	NO_AUTO_CAPTURE     = C.PCRE2_NO_AUTO_CAPTURE     /* C       */
	NO_AUTO_POSSESS     = C.PCRE2_NO_AUTO_POSSESS     /* C       */
	NO_DOTSTAR_ANCHOR   = C.PCRE2_NO_DOTSTAR_ANCHOR   /* C       */
	NO_START_OPTIMIZE   = C.PCRE2_NO_START_OPTIMIZE   /*   J M D */
	UCP                 = C.PCRE2_UCP                 /* C J M D */
	UNGREEDY            = C.PCRE2_UNGREEDY            /* C       */
	UTF                 = C.PCRE2_UTF                 /* C J M D */
	NEVER_BACKSLASH_C   = C.PCRE2_NEVER_BACKSLASH_C   /* C       */
	ALT_CIRCUMFLEX      = C.PCRE2_ALT_CIRCUMFLEX      /*   J M D */
	ALT_VERBNAMES       = C.PCRE2_ALT_VERBNAMES       /* C       */
	USE_OFFSET_LIMIT    = C.PCRE2_USE_OFFSET_LIMIT    /*   J M D */
	EXTENDED_MORE       = C.PCRE2_EXTENDED_MORE       /* C       */
	LITERAL             = C.PCRE2_LITERAL             /* C       */
)

// An additional compile options word is available in the compile context.
const (
	EXTRA_ALLOW_SURROGATE_ESCAPES = C.PCRE2_EXTRA_ALLOW_SURROGATE_ESCAPES /* C */
	EXTRA_BAD_ESCAPE_IS_LITERAL   = C.PCRE2_EXTRA_BAD_ESCAPE_IS_LITERAL   /* C */
	EXTRA_MATCH_WORD              = C.PCRE2_EXTRA_MATCH_WORD              /* C */
	EXTRA_MATCH_LINE              = C.PCRE2_EXTRA_MATCH_LINE              /* C */
)

// These are for JITCompile()
const (
	JIT_COMPLETE     = C.PCRE2_JIT_COMPLETE /* For full matching */
	JIT_PARTIAL_SOFT = C.PCRE2_JIT_PARTIAL_SOFT
	JIT_PARTIAL_HARD = C.PCRE2_JIT_PARTIAL_HARD
)

// These are for Match() and DfaMatch(). Note that ANCHORED,
// and NO_UTF_CHECK can also be passed to these functions, so take care not
// to define synonyms by mistake.
const (
	NOTBOL           = C.PCRE2_NOTBOL
	NOTEOL           = C.PCRE2_NOTEOL
	NOTEMPTY         = C.PCRE2_NOTEMPTY         /* ) These two must be kept */
	NOTEMPTY_ATSTART = C.PCRE2_NOTEMPTY_ATSTART /* ) adjacent to each other. */
	PARTIAL_SOFT     = C.PCRE2_PARTIAL_SOFT
	PARTIAL_HARD     = C.PCRE2_PARTIAL_HARD
)

// These are additional options for DfaMatch().
const (
	DFA_RESTART  = C.PCRE2_DFA_RESTART
	DFA_SHORTEST = C.PCRE2_DFA_SHORTEST
)

// These are additional options for Substitute(), which passes any others
// through to Match().
const (
	SUBSTITUTE_GLOBAL          = C.PCRE2_SUBSTITUTE_GLOBAL
	SUBSTITUTE_EXTENDED        = C.PCRE2_SUBSTITUTE_EXTENDED
	SUBSTITUTE_UNSET_EMPTY     = C.PCRE2_SUBSTITUTE_UNSET_EMPTY
	SUBSTITUTE_UNKNOWN_UNSET   = C.PCRE2_SUBSTITUTE_UNKNOWN_UNSET
	SUBSTITUTE_OVERFLOW_LENGTH = C.PCRE2_SUBSTITUTE_OVERFLOW_LENGTH
)

// A further option for Match(), not allowed for DfaMatch(), ignored for JITMatch().
const (
	NO_JIT = C.PCRE2_NO_JIT
)

// Options for pcre2_pattern_convert().
const (
	CONVERT_UTF                    = C.PCRE2_CONVERT_UTF
	CONVERT_NO_UTF_CHECK           = C.PCRE2_CONVERT_NO_UTF_CHECK
	CONVERT_POSIX_BASIC            = C.PCRE2_CONVERT_POSIX_BASIC
	CONVERT_POSIX_EXTENDED         = C.PCRE2_CONVERT_POSIX_EXTENDED
	CONVERT_GLOB                   = C.PCRE2_CONVERT_GLOB
	CONVERT_GLOB_NO_WILD_SEPARATOR = C.PCRE2_CONVERT_GLOB_NO_WILD_SEPARATOR
	CONVERT_GLOB_NO_STARSTAR       = C.PCRE2_CONVERT_GLOB_NO_STARSTAR
)

// Newline and \R settings, for use in compile contexts. The newline values
// must be kept in step with values set in config.h and both sets must all be
// greater than zero.
const (
	NEWLINE_CR      = C.PCRE2_NEWLINE_CR
	NEWLINE_LF      = C.PCRE2_NEWLINE_LF
	NEWLINE_CRLF    = C.PCRE2_NEWLINE_CRLF
	NEWLINE_ANY     = C.PCRE2_NEWLINE_ANY
	NEWLINE_ANYCRLF = C.PCRE2_NEWLINE_ANYCRLF
	NEWLINE_NUL     = C.PCRE2_NEWLINE_NUL

	BSR_UNICODE = C.PCRE2_BSR_UNICODE
	BSR_ANYCRLF = C.PCRE2_BSR_ANYCRLF
)

// Error codes for Compile(). Some of these are also used by PatternConvert().
const (
	ERROR_END_BACKSLASH                  = C.PCRE2_ERROR_END_BACKSLASH
	ERROR_END_BACKSLASH_C                = C.PCRE2_ERROR_END_BACKSLASH_C
	ERROR_UNKNOWN_ESCAPE                 = C.PCRE2_ERROR_UNKNOWN_ESCAPE
	ERROR_QUANTIFIER_OUT_OF_ORDER        = C.PCRE2_ERROR_QUANTIFIER_OUT_OF_ORDER
	ERROR_QUANTIFIER_TOO_BIG             = C.PCRE2_ERROR_QUANTIFIER_TOO_BIG
	ERROR_MISSING_SQUARE_BRACKET         = C.PCRE2_ERROR_MISSING_SQUARE_BRACKET
	ERROR_ESCAPE_INVALID_IN_CLASS        = C.PCRE2_ERROR_ESCAPE_INVALID_IN_CLASS
	ERROR_CLASS_RANGE_ORDER              = C.PCRE2_ERROR_CLASS_RANGE_ORDER
	ERROR_QUANTIFIER_INVALID             = C.PCRE2_ERROR_QUANTIFIER_INVALID
	ERROR_INTERNAL_UNEXPECTED_REPEAT     = C.PCRE2_ERROR_INTERNAL_UNEXPECTED_REPEAT
	ERROR_INVALID_AFTER_PARENS_QUERY     = C.PCRE2_ERROR_INVALID_AFTER_PARENS_QUERY
	ERROR_POSIX_CLASS_NOT_IN_CLASS       = C.PCRE2_ERROR_POSIX_CLASS_NOT_IN_CLASS
	ERROR_POSIX_NO_SUPPORT_COLLATING     = C.PCRE2_ERROR_POSIX_NO_SUPPORT_COLLATING
	ERROR_MISSING_CLOSING_PARENTHESIS    = C.PCRE2_ERROR_MISSING_CLOSING_PARENTHESIS
	ERROR_BAD_SUBPATTERN_REFERENCE       = C.PCRE2_ERROR_BAD_SUBPATTERN_REFERENCE
	ERROR_NULL_PATTERN                   = C.PCRE2_ERROR_NULL_PATTERN
	ERROR_BAD_OPTIONS                    = C.PCRE2_ERROR_BAD_OPTIONS
	ERROR_MISSING_COMMENT_CLOSING        = C.PCRE2_ERROR_MISSING_COMMENT_CLOSING
	ERROR_PARENTHESES_NEST_TOO_DEEP      = C.PCRE2_ERROR_PARENTHESES_NEST_TOO_DEEP
	ERROR_PATTERN_TOO_LARGE              = C.PCRE2_ERROR_PATTERN_TOO_LARGE
	ERROR_HEAP_FAILED                    = C.PCRE2_ERROR_HEAP_FAILED
	ERROR_UNMATCHED_CLOSING_PARENTHESIS  = C.PCRE2_ERROR_UNMATCHED_CLOSING_PARENTHESIS
	ERROR_INTERNAL_CODE_OVERFLOW         = C.PCRE2_ERROR_INTERNAL_CODE_OVERFLOW
	ERROR_MISSING_CONDITION_CLOSING      = C.PCRE2_ERROR_MISSING_CONDITION_CLOSING
	ERROR_LOOKBEHIND_NOT_FIXED_LENGTH    = C.PCRE2_ERROR_LOOKBEHIND_NOT_FIXED_LENGTH
	ERROR_ZERO_RELATIVE_REFERENCE        = C.PCRE2_ERROR_ZERO_RELATIVE_REFERENCE
	ERROR_TOO_MANY_CONDITION_BRANCHES    = C.PCRE2_ERROR_TOO_MANY_CONDITION_BRANCHES
	ERROR_CONDITION_ASSERTION_EXPECTED   = C.PCRE2_ERROR_CONDITION_ASSERTION_EXPECTED
	ERROR_BAD_RELATIVE_REFERENCE         = C.PCRE2_ERROR_BAD_RELATIVE_REFERENCE
	ERROR_UNKNOWN_POSIX_CLASS            = C.PCRE2_ERROR_UNKNOWN_POSIX_CLASS
	ERROR_INTERNAL_STUDY_ERROR           = C.PCRE2_ERROR_INTERNAL_STUDY_ERROR
	ERROR_UNICODE_NOT_SUPPORTED          = C.PCRE2_ERROR_UNICODE_NOT_SUPPORTED
	ERROR_PARENTHESES_STACK_CHECK        = C.PCRE2_ERROR_PARENTHESES_STACK_CHECK
	ERROR_CODE_POINT_TOO_BIG             = C.PCRE2_ERROR_CODE_POINT_TOO_BIG
	ERROR_LOOKBEHIND_TOO_COMPLICATED     = C.PCRE2_ERROR_LOOKBEHIND_TOO_COMPLICATED
	ERROR_LOOKBEHIND_INVALID_BACKSLASH_C = C.PCRE2_ERROR_LOOKBEHIND_INVALID_BACKSLASH_C
	ERROR_UNSUPPORTED_ESCAPE_SEQUENCE    = C.PCRE2_ERROR_UNSUPPORTED_ESCAPE_SEQUENCE
	ERROR_CALLOUT_NUMBER_TOO_BIG         = C.PCRE2_ERROR_CALLOUT_NUMBER_TOO_BIG
	ERROR_MISSING_CALLOUT_CLOSING        = C.PCRE2_ERROR_MISSING_CALLOUT_CLOSING
	ERROR_ESCAPE_INVALID_IN_VERB         = C.PCRE2_ERROR_ESCAPE_INVALID_IN_VERB
	ERROR_UNRECOGNIZED_AFTER_QUERY_P     = C.PCRE2_ERROR_UNRECOGNIZED_AFTER_QUERY_P
	ERROR_MISSING_NAME_TERMINATOR        = C.PCRE2_ERROR_MISSING_NAME_TERMINATOR
	ERROR_DUPLICATE_SUBPATTERN_NAME      = C.PCRE2_ERROR_DUPLICATE_SUBPATTERN_NAME
	ERROR_INVALID_SUBPATTERN_NAME        = C.PCRE2_ERROR_INVALID_SUBPATTERN_NAME
	ERROR_UNICODE_PROPERTIES_UNAVAILABLE = C.PCRE2_ERROR_UNICODE_PROPERTIES_UNAVAILABLE
	ERROR_MALFORMED_UNICODE_PROPERTY     = C.PCRE2_ERROR_MALFORMED_UNICODE_PROPERTY
	ERROR_UNKNOWN_UNICODE_PROPERTY       = C.PCRE2_ERROR_UNKNOWN_UNICODE_PROPERTY
	ERROR_SUBPATTERN_NAME_TOO_LONG       = C.PCRE2_ERROR_SUBPATTERN_NAME_TOO_LONG
	ERROR_TOO_MANY_NAMED_SUBPATTERNS     = C.PCRE2_ERROR_TOO_MANY_NAMED_SUBPATTERNS
	ERROR_CLASS_INVALID_RANGE            = C.PCRE2_ERROR_CLASS_INVALID_RANGE
	ERROR_OCTAL_BYTE_TOO_BIG             = C.PCRE2_ERROR_OCTAL_BYTE_TOO_BIG
	ERROR_INTERNAL_OVERRAN_WORKSPACE     = C.PCRE2_ERROR_INTERNAL_OVERRAN_WORKSPACE
	ERROR_INTERNAL_MISSING_SUBPATTERN    = C.PCRE2_ERROR_INTERNAL_MISSING_SUBPATTERN
	ERROR_DEFINE_TOO_MANY_BRANCHES       = C.PCRE2_ERROR_DEFINE_TOO_MANY_BRANCHES
	ERROR_BACKSLASH_O_MISSING_BRACE      = C.PCRE2_ERROR_BACKSLASH_O_MISSING_BRACE
	ERROR_INTERNAL_UNKNOWN_NEWLINE       = C.PCRE2_ERROR_INTERNAL_UNKNOWN_NEWLINE
	ERROR_BACKSLASH_G_SYNTAX             = C.PCRE2_ERROR_BACKSLASH_G_SYNTAX
	ERROR_PARENS_QUERY_R_MISSING_CLOSING = C.PCRE2_ERROR_PARENS_QUERY_R_MISSING_CLOSING
	/* Error 159 is obsolete and should now never occur */
	ERROR_VERB_ARGUMENT_NOT_ALLOWED      = C.PCRE2_ERROR_VERB_ARGUMENT_NOT_ALLOWED
	ERROR_VERB_UNKNOWN                   = C.PCRE2_ERROR_VERB_UNKNOWN
	ERROR_SUBPATTERN_NUMBER_TOO_BIG      = C.PCRE2_ERROR_SUBPATTERN_NUMBER_TOO_BIG
	ERROR_SUBPATTERN_NAME_EXPECTED       = C.PCRE2_ERROR_SUBPATTERN_NAME_EXPECTED
	ERROR_INTERNAL_PARSED_OVERFLOW       = C.PCRE2_ERROR_INTERNAL_PARSED_OVERFLOW
	ERROR_INVALID_OCTAL                  = C.PCRE2_ERROR_INVALID_OCTAL
	ERROR_SUBPATTERN_NAMES_MISMATCH      = C.PCRE2_ERROR_SUBPATTERN_NAMES_MISMATCH
	ERROR_MARK_MISSING_ARGUMENT          = C.PCRE2_ERROR_MARK_MISSING_ARGUMENT
	ERROR_INVALID_HEXADECIMAL            = C.PCRE2_ERROR_INVALID_HEXADECIMAL
	ERROR_BACKSLASH_C_SYNTAX             = C.PCRE2_ERROR_BACKSLASH_C_SYNTAX
	ERROR_BACKSLASH_K_SYNTAX             = C.PCRE2_ERROR_BACKSLASH_K_SYNTAX
	ERROR_INTERNAL_BAD_CODE_LOOKBEHINDS  = C.PCRE2_ERROR_INTERNAL_BAD_CODE_LOOKBEHINDS
	ERROR_BACKSLASH_N_IN_CLASS           = C.PCRE2_ERROR_BACKSLASH_N_IN_CLASS
	ERROR_CALLOUT_STRING_TOO_LONG        = C.PCRE2_ERROR_CALLOUT_STRING_TOO_LONG
	ERROR_UNICODE_DISALLOWED_CODE_POINT  = C.PCRE2_ERROR_UNICODE_DISALLOWED_CODE_POINT
	ERROR_UTF_IS_DISABLED                = C.PCRE2_ERROR_UTF_IS_DISABLED
	ERROR_UCP_IS_DISABLED                = C.PCRE2_ERROR_UCP_IS_DISABLED
	ERROR_VERB_NAME_TOO_LONG             = C.PCRE2_ERROR_VERB_NAME_TOO_LONG
	ERROR_BACKSLASH_U_CODE_POINT_TOO_BIG = C.PCRE2_ERROR_BACKSLASH_U_CODE_POINT_TOO_BIG
	ERROR_MISSING_OCTAL_OR_HEX_DIGITS    = C.PCRE2_ERROR_MISSING_OCTAL_OR_HEX_DIGITS
	ERROR_VERSION_CONDITION_SYNTAX       = C.PCRE2_ERROR_VERSION_CONDITION_SYNTAX
	ERROR_INTERNAL_BAD_CODE_AUTO_POSSESS = C.PCRE2_ERROR_INTERNAL_BAD_CODE_AUTO_POSSESS
	ERROR_CALLOUT_NO_STRING_DELIMITER    = C.PCRE2_ERROR_CALLOUT_NO_STRING_DELIMITER
	ERROR_CALLOUT_BAD_STRING_DELIMITER   = C.PCRE2_ERROR_CALLOUT_BAD_STRING_DELIMITER
	ERROR_BACKSLASH_C_CALLER_DISABLED    = C.PCRE2_ERROR_BACKSLASH_C_CALLER_DISABLED
	ERROR_QUERY_BARJX_NEST_TOO_DEEP      = C.PCRE2_ERROR_QUERY_BARJX_NEST_TOO_DEEP
	ERROR_BACKSLASH_C_LIBRARY_DISABLED   = C.PCRE2_ERROR_BACKSLASH_C_LIBRARY_DISABLED
	ERROR_PATTERN_TOO_COMPLICATED        = C.PCRE2_ERROR_PATTERN_TOO_COMPLICATED
	ERROR_LOOKBEHIND_TOO_LONG            = C.PCRE2_ERROR_LOOKBEHIND_TOO_LONG
	ERROR_PATTERN_STRING_TOO_LONG        = C.PCRE2_ERROR_PATTERN_STRING_TOO_LONG
	ERROR_INTERNAL_BAD_CODE              = C.PCRE2_ERROR_INTERNAL_BAD_CODE
	ERROR_INTERNAL_BAD_CODE_IN_SKIP      = C.PCRE2_ERROR_INTERNAL_BAD_CODE_IN_SKIP
	ERROR_NO_SURROGATES_IN_UTF16         = C.PCRE2_ERROR_NO_SURROGATES_IN_UTF16
	ERROR_BAD_LITERAL_OPTIONS            = C.PCRE2_ERROR_BAD_LITERAL_OPTIONS
	ERROR_SUPPORTED_ONLY_IN_UNICODE      = C.PCRE2_ERROR_SUPPORTED_ONLY_IN_UNICODE
	ERROR_INVALID_HYPHEN_IN_OPTIONS      = C.PCRE2_ERROR_INVALID_HYPHEN_IN_OPTIONS
)

// "Expected" matching error codes: no match and partial match.
const (
	ERROR_NOMATCH = C.PCRE2_ERROR_NOMATCH
	ERROR_PARTIAL = C.PCRE2_ERROR_PARTIAL
)

// Error codes for UTF-8 validity checks
const (
	ERROR_UTF8_ERR1  = C.PCRE2_ERROR_UTF8_ERR1
	ERROR_UTF8_ERR2  = C.PCRE2_ERROR_UTF8_ERR2
	ERROR_UTF8_ERR3  = C.PCRE2_ERROR_UTF8_ERR3
	ERROR_UTF8_ERR4  = C.PCRE2_ERROR_UTF8_ERR4
	ERROR_UTF8_ERR5  = C.PCRE2_ERROR_UTF8_ERR5
	ERROR_UTF8_ERR6  = C.PCRE2_ERROR_UTF8_ERR6
	ERROR_UTF8_ERR7  = C.PCRE2_ERROR_UTF8_ERR7
	ERROR_UTF8_ERR8  = C.PCRE2_ERROR_UTF8_ERR8
	ERROR_UTF8_ERR9  = C.PCRE2_ERROR_UTF8_ERR9
	ERROR_UTF8_ERR10 = C.PCRE2_ERROR_UTF8_ERR10
	ERROR_UTF8_ERR11 = C.PCRE2_ERROR_UTF8_ERR11
	ERROR_UTF8_ERR12 = C.PCRE2_ERROR_UTF8_ERR12
	ERROR_UTF8_ERR13 = C.PCRE2_ERROR_UTF8_ERR13
	ERROR_UTF8_ERR14 = C.PCRE2_ERROR_UTF8_ERR14
	ERROR_UTF8_ERR15 = C.PCRE2_ERROR_UTF8_ERR15
	ERROR_UTF8_ERR16 = C.PCRE2_ERROR_UTF8_ERR16
	ERROR_UTF8_ERR17 = C.PCRE2_ERROR_UTF8_ERR17
	ERROR_UTF8_ERR18 = C.PCRE2_ERROR_UTF8_ERR18
	ERROR_UTF8_ERR19 = C.PCRE2_ERROR_UTF8_ERR19
	ERROR_UTF8_ERR20 = C.PCRE2_ERROR_UTF8_ERR20
	ERROR_UTF8_ERR21 = C.PCRE2_ERROR_UTF8_ERR21
)

// Error codes for UTF-16 validity checks
const (
	ERROR_UTF16_ERR1 = C.PCRE2_ERROR_UTF16_ERR1
	ERROR_UTF16_ERR2 = C.PCRE2_ERROR_UTF16_ERR2
	ERROR_UTF16_ERR3 = C.PCRE2_ERROR_UTF16_ERR3
)

// Error codes for UTF-32 validity checks
const (
	ERROR_UTF32_ERR1 = C.PCRE2_ERROR_UTF32_ERR1
	ERROR_UTF32_ERR2 = C.PCRE2_ERROR_UTF32_ERR2
)

// Error codes for [Dfa]Match(), substring extraction functions, context
// functions, and serializing functions. They are in numerical order. Originally
// they were in alphabetical order too, but now that PCRE2 is released, the
// numbers must not be changed.
const (
	ERROR_BADDATA           = C.PCRE2_ERROR_BADDATA
	ERROR_MIXEDTABLES       = C.PCRE2_ERROR_MIXEDTABLES /* Name was changed */
	ERROR_BADMAGIC          = C.PCRE2_ERROR_BADMAGIC
	ERROR_BADMODE           = C.PCRE2_ERROR_BADMODE
	ERROR_BADOFFSET         = C.PCRE2_ERROR_BADOFFSET
	ERROR_BADOPTION         = C.PCRE2_ERROR_BADOPTION
	ERROR_BADREPLACEMENT    = C.PCRE2_ERROR_BADREPLACEMENT
	ERROR_BADUTFOFFSET      = C.PCRE2_ERROR_BADUTFOFFSET
	ERROR_CALLOUT           = C.PCRE2_ERROR_CALLOUT /* Never used by PCRE2 itself */
	ERROR_DFA_BADRESTART    = C.PCRE2_ERROR_DFA_BADRESTART
	ERROR_DFA_RECURSE       = C.PCRE2_ERROR_DFA_RECURSE
	ERROR_DFA_UCOND         = C.PCRE2_ERROR_DFA_UCOND
	ERROR_DFA_UFUNC         = C.PCRE2_ERROR_DFA_UFUNC
	ERROR_DFA_UITEM         = C.PCRE2_ERROR_DFA_UITEM
	ERROR_DFA_WSSIZE        = C.PCRE2_ERROR_DFA_WSSIZE
	ERROR_INTERNAL          = C.PCRE2_ERROR_INTERNAL
	ERROR_JIT_BADOPTION     = C.PCRE2_ERROR_JIT_BADOPTION
	ERROR_JIT_STACKLIMIT    = C.PCRE2_ERROR_JIT_STACKLIMIT
	ERROR_MATCHLIMIT        = C.PCRE2_ERROR_MATCHLIMIT
	ERROR_NOMEMORY          = C.PCRE2_ERROR_NOMEMORY
	ERROR_NOSUBSTRING       = C.PCRE2_ERROR_NOSUBSTRING
	ERROR_NOUNIQUESUBSTRING = C.PCRE2_ERROR_NOUNIQUESUBSTRING
	ERROR_NULL              = C.PCRE2_ERROR_NULL
	ERROR_RECURSELOOP       = C.PCRE2_ERROR_RECURSELOOP
	ERROR_RECURSIONLIMIT    = C.PCRE2_ERROR_RECURSIONLIMIT /* Obsolete synonym */
	ERROR_UNAVAILABLE       = C.PCRE2_ERROR_UNAVAILABLE
	ERROR_UNSET             = C.PCRE2_ERROR_UNSET
	ERROR_BADOFFSETLIMIT    = C.PCRE2_ERROR_BADOFFSETLIMIT
	ERROR_BADREPESCAPE      = C.PCRE2_ERROR_BADREPESCAPE
	ERROR_REPMISSINGBRACE   = C.PCRE2_ERROR_REPMISSINGBRACE
	ERROR_BADSUBSTITUTION   = C.PCRE2_ERROR_BADSUBSTITUTION
	ERROR_BADSUBSPATTERN    = C.PCRE2_ERROR_BADSUBSPATTERN
	ERROR_TOOMANYREPLACE    = C.PCRE2_ERROR_TOOMANYREPLACE
	ERROR_BADSERIALIZEDDATA = C.PCRE2_ERROR_BADSERIALIZEDDATA
	ERROR_HEAPLIMIT         = C.PCRE2_ERROR_HEAPLIMIT
	ERROR_CONVERT_SYNTAX    = C.PCRE2_ERROR_CONVERT_SYNTAX
	ERROR_INTERNAL_DUPMATCH = C.PCRE2_ERROR_INTERNAL_DUPMATCH
)

// Request types for PatternInfo()
const (
	INFO_ALLOPTIONS     = C.PCRE2_INFO_ALLOPTIONS
	INFO_ARGOPTIONS     = C.PCRE2_INFO_ARGOPTIONS
	INFO_BACKREFMAX     = C.PCRE2_INFO_BACKREFMAX
	INFO_BSR            = C.PCRE2_INFO_BSR
	INFO_CAPTURECOUNT   = C.PCRE2_INFO_CAPTURECOUNT
	INFO_FIRSTCODEUNIT  = C.PCRE2_INFO_FIRSTCODEUNIT
	INFO_FIRSTCODETYPE  = C.PCRE2_INFO_FIRSTCODETYPE
	INFO_FIRSTBITMAP    = C.PCRE2_INFO_FIRSTBITMAP
	INFO_HASCRORLF      = C.PCRE2_INFO_HASCRORLF
	INFO_JCHANGED       = C.PCRE2_INFO_JCHANGED
	INFO_JITSIZE        = C.PCRE2_INFO_JITSIZE
	INFO_LASTCODEUNIT   = C.PCRE2_INFO_LASTCODEUNIT
	INFO_LASTCODETYPE   = C.PCRE2_INFO_LASTCODETYPE
	INFO_MATCHEMPTY     = C.PCRE2_INFO_MATCHEMPTY
	INFO_MATCHLIMIT     = C.PCRE2_INFO_MATCHLIMIT
	INFO_MAXLOOKBEHIND  = C.PCRE2_INFO_MAXLOOKBEHIND
	INFO_MINLENGTH      = C.PCRE2_INFO_MINLENGTH
	INFO_NAMECOUNT      = C.PCRE2_INFO_NAMECOUNT
	INFO_NAMEENTRYSIZE  = C.PCRE2_INFO_NAMEENTRYSIZE
	INFO_NAMETABLE      = C.PCRE2_INFO_NAMETABLE
	INFO_NEWLINE        = C.PCRE2_INFO_NEWLINE
	INFO_RECURSIONLIMIT = C.PCRE2_INFO_RECURSIONLIMIT /* Obsolete synonym */
	INFO_SIZE           = C.PCRE2_INFO_SIZE
	INFO_HASBACKSLASHC  = C.PCRE2_INFO_HASBACKSLASHC
	INFO_FRAMESIZE      = C.PCRE2_INFO_FRAMESIZE
	INFO_HEAPLIMIT      = C.PCRE2_INFO_HEAPLIMIT
	INFO_EXTRAOPTIONS   = C.PCRE2_INFO_EXTRAOPTIONS
)

// Request types for Config().
const (
	CONFIG_BSR               = C.PCRE2_CONFIG_BSR
	CONFIG_JIT               = C.PCRE2_CONFIG_JIT
	CONFIG_JITTARGET         = C.PCRE2_CONFIG_JITTARGET
	CONFIG_LINKSIZE          = C.PCRE2_CONFIG_LINKSIZE
	CONFIG_MATCHLIMIT        = C.PCRE2_CONFIG_MATCHLIMIT
	CONFIG_NEWLINE           = C.PCRE2_CONFIG_NEWLINE
	CONFIG_PARENSLIMIT       = C.PCRE2_CONFIG_PARENSLIMIT
	CONFIG_RECURSIONLIMIT    = C.PCRE2_CONFIG_RECURSIONLIMIT /* Obsolete synonym */
	CONFIG_STACKRECURSE      = C.PCRE2_CONFIG_STACKRECURSE   /* Obsolete */
	CONFIG_UNICODE           = C.PCRE2_CONFIG_UNICODE
	CONFIG_UNICODE_VERSION   = C.PCRE2_CONFIG_UNICODE_VERSION
	CONFIG_VERSION           = C.PCRE2_CONFIG_VERSION
	CONFIG_HEAPLIMIT         = C.PCRE2_CONFIG_HEAPLIMIT
	CONFIG_NEVER_BACKSLASH_C = C.PCRE2_CONFIG_NEVER_BACKSLASH_C
	CONFIG_COMPILED_WIDTHS   = C.PCRE2_CONFIG_COMPILED_WIDTHS
)

// We define special values to indicate zero-terminated strings and unset offsets in
// the offset vector (ovector).
const (
	ZERO_TERMINATED = C.PCRE2_ZERO_TERMINATED
	UNSET           = C.PCRE2_UNSET
)

// Constants used to determine the right size of the matchData structure
var (
	pcre2Size             int
	myStaticMatchDataSize int
	contextSize           int
)

func init() {
	C.myInitSizes()
	pcre2Size = int(C.myPcre2Size)
	myStaticMatchDataSize = int(C.myStaticMatchDataSize)
	contextSize = int(C.myContextSize)
}

var (
	// ErrInvalidRegexp is returned when the provided Regexp is
	// not backed by a proper C pointer to pcre2_code
	ErrInvalidRegexp = errors.New("invalid regexp")
)

// Regexp holds a reference to a compiled regular expression.
// Use Compile or MustCompile to create such objects.
type Regexp struct {
	Pattern string
	ptr     *C.pcre2_code
	cleanup sync.Once
}

// Number of bytes in the compiled pattern
func pcreSize(ptr *C.pcre2_code) (size C.PCRE2_SIZE) {
	C.pcre2_pattern_info(ptr, INFO_SIZE, unsafe.Pointer(&size))
	return
}

// Number of capture groups
func pcreGroups(ptr *C.pcre2_code) (count C.PCRE2_SIZE) {
	C.pcre2_pattern_info(ptr, INFO_CAPTURECOUNT, unsafe.Pointer(&count))
	return
}

type matchData struct {
	md      *C.pcre2_match_data
	ovector []C.PCRE2_SIZE
	cleanup sync.Once
}

func finalizeMatchData(m *matchData) {
	if m != nil && m.md != nil {
		m.cleanup.Do(func() {
			m.ovector = []C.PCRE2_SIZE{}
			C.pcre2_match_data_free(m.md)
			m.md = nil
		})
	}
}

func (md *matchData) ensureNotFreed() {
	if md == nil {
		panic("Use after free")
	}
}

// We don't use pcre2_match_data_create, because we want this to be in Go memory.
// This way it's garbage collected.
func (re *Regexp) matchDataCreate() (result *matchData) {
	result = &matchData{}
	oveccount := re.Groups() + 1

	result.md = C.pcre2_match_data_create_from_pattern(re.ptr, nil)
	povec := C.pcre2_get_ovector_pointer(result.md)
	ovecHead := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(povec)),
		Len:  2 * oveccount,
		Cap:  2 * oveccount,
	}
	result.ovector = *(*[]C.PCRE2_SIZE)(unsafe.Pointer(&ovecHead))
	runtime.SetFinalizer(result, finalizeMatchData)
	return
}

// Compile the pattern and return a compiled regexp.
// If compilation fails, the second return value holds a *CompileError.
func Compile(pattern string, flags uint32) (*Regexp, error) {
	pattern1 := C.CString(pattern)
	defer C.free(unsafe.Pointer(pattern1))
	if clen := int(C.strlen(pattern1)); clen != len(pattern) {
		return nil, &CompileError{
			Pattern: pattern,
			Message: "NUL byte in pattern",
			Offset:  clen,
		}
	}
	var errnum C.int
	var erroffset C.PCRE2_SIZE
	ptr := C.pcre2_compile(
		C.PCRE2_SPTR(unsafe.Pointer(pattern1)),
		C.size_t(len(pattern)),
		C.uint32_t(flags),
		&errnum,
		&erroffset,
		nil,
	)
	if ptr == nil {
		rawbytes := C.MY_pcre2_get_error_message(errnum)
		msg := C.GoString((*C.char)(rawbytes))
		C.free(unsafe.Pointer(rawbytes))

		return nil, &CompileError{
			Pattern: pattern,
			Message: msg,
			Offset:  int(erroffset),
		}
	}
	re := &Regexp{
		Pattern: pattern,
		ptr:     ptr,
	}
	runtime.SetFinalizer(re, finalizeRegex)
	return re, nil
}

// CompileJIT is a combination of Compile and Study. It first compiles
// the pattern and if this succeeds calls Study on the compiled pattern.
// comFlags are Compile flags, jitFlags are study flags.
// If compilation fails, the second return value holds a *CompileError.
func CompileJIT(pattern string, comFlags, jitFlags uint32) (*Regexp, error) {
	re, err := Compile(pattern, comFlags)
	if err == nil {
		err = re.JITCompile(jitFlags)
	}
	return re, err
}

// MustCompile compiles the pattern. If compilation fails, panic.
func MustCompile(pattern string, flags uint32) (re *Regexp) {
	re, err := Compile(pattern, flags)
	if err != nil {
		panic(err)
	}
	return
}

// MustCompileJIT compiles and studies the pattern. On failure it panics.
func MustCompileJIT(pattern string, comFlags, jitFlags uint32) (re *Regexp) {
	re, err := CompileJIT(pattern, comFlags, jitFlags)
	if err != nil {
		panic(err)
	}
	return
}

// JITCompile adds Just-In-Time compilation to a Regexp. This may give a huge
// speed boost when matching. If an error occurs, return value is non-nil.
// Flags optionally specifies JIT compilation options for partial matches.
// The returned value from JITCompile() is nil on success, or an error otherwise.
// If JIT support is not available, a call to JITCompile() does nothing and returns ERROR_JIT_BADOPTION.
func (re *Regexp) JITCompile(flags uint32) error {
	rptr, err := re.validRegexpPtr()
	if err != nil {
		return err
	}
	res := C.pcre2_jit_compile(rptr, C.uint(flags))
	if res != 0 {
		rawbytes := C.MY_pcre2_get_error_message(res)
		msg := C.GoString((*C.char)(rawbytes))
		C.free(unsafe.Pointer(rawbytes))
		return &JITError{
			ErrorNum: int(res),
			Message:  msg,
		}
	}
	return nil
}

func (re *Regexp) validRegexpPtr() (*C.pcre2_code, error) {
	if re == nil {
		return nil, ErrInvalidRegexp
	}

	if rptr := re.ptr; rptr != nil {
		return (*C.pcre2_code)(unsafe.Pointer(rptr)), nil
	}
	return nil, ErrInvalidRegexp
}

func finalizeRegex(r *Regexp) {
	if r != nil && r.ptr != nil {
		r.cleanup.Do(func() {
			C.pcre2_code_free(r.ptr)
			r.ptr = nil
		})
	}
}

// Free releases the underlying C resources
func (re *Regexp) Free() error {
	if re == nil || re.ptr == nil {
		return nil
	}
	finalizeRegex(re)
	runtime.SetFinalizer(re, nil)
	return nil
}

// Groups returns the number of capture groups in the compiled pattern.
func (re *Regexp) Groups() int {
	if re.ptr == nil {
		panic("Regexp.Groups: uninitialized")
	}
	return int(pcreGroups(re.ptr))
}

// Matcher objects provide a place for storing match results.
// They can be created by the Matcher and MatcherString functions,
// or they can be initialized with Reset or ResetString.
type Matcher struct {
	re       *Regexp
	groups   int
	mData    *matchData
	matches  bool   // last match was successful
	partial  bool   // was the last match a partial match?
	rc       int    // return code of the match function, useful to know if there was an error
	subjects string // one of these fields is set to record the subject,
	subjectb []byte // so that Group/GroupString can return slices
}

// NewMatcher creates a new matcher object for the given Regexp.
func (re *Regexp) NewMatcher() (m *Matcher) {
	m = new(Matcher)
	m.Init(re)
	return
}

// Matcher creates a new matcher object, with the byte slice as subject.
// It also starts a first match on subject. Test for success with Matches().
func (re *Regexp) Matcher(subject []byte, flags uint32) (m *Matcher) {
	m = re.NewMatcher()
	m.Match(subject, flags)
	return
}

// MatcherString creates a new matcher, with the specified subject string.
// It also starts a first match on subject. Test for success with Matches().
func (re *Regexp) MatcherString(subject string, flags uint32) (m *Matcher) {
	m = re.NewMatcher()
	m.MatchString(subject, flags)
	return
}

// Reset switches the matcher object to the specified regexp and subject.
// It also starts a first match on subject.
func (m *Matcher) Reset(re *Regexp, subject []byte, flags uint32) bool {
	m.Init(re)
	return m.Match(subject, flags)
}

// ResetString switches the matcher object to the given regexp and subject.
// It also starts a first match on subject.
func (m *Matcher) ResetString(re *Regexp, subject string, flags uint32) bool {
	m.Init(re)
	return m.MatchString(subject, flags)
}

// Init binds an existing Matcher object to the given Regexp.
func (m *Matcher) Init(re *Regexp) {
	if re.ptr == nil {
		panic("Matcher.Init: uninitialized")
	}
	m.matches = false
	if m.re != nil && m.re.ptr != nil && m.re.ptr == re.ptr {
		// Skip group count extraction if the matcher has
		// already been initialized with the same regular
		// expression.
		return
	}
	m.re = re
	m.groups = re.Groups()
	m.mData = re.matchDataCreate()
}

var nullbyte = []byte{0}

// Match tries to match the specified byte slice to
// the current pattern by calling Exec and collects the result.
// Returns true if the match succeeds.
func (m *Matcher) Match(subject []byte, flags uint32) bool {
	if m.re.ptr == nil {
		panic("Matcher.Match: uninitialized")
	}
	rc := m.Exec(subject, flags)
	m.rc = rc
	m.matches = matched(rc)
	m.partial = (rc == ERROR_PARTIAL)
	return m.matches
}

// MatchString tries to match the specified subject string to
// the current pattern by calling ExecString and collects the result.
// Returns true if the match succeeds.
func (m *Matcher) MatchString(subject string, flags uint32) bool {
	if m.re.ptr == nil {
		panic("Matcher.MatchString: uninitialized")
	}
	rc := m.ExecString(subject, flags)
	m.rc = rc
	m.matches = matched(rc)
	m.partial = (rc == ERROR_PARTIAL)
	return m.matches
}

// Exec tries to match the specified byte slice to
// the current pattern. Returns the raw pcre_exec error code.
func (m *Matcher) Exec(subject []byte, flags uint32) int {
	if m.re.ptr == nil {
		panic("Matcher.Exec: uninitialized")
	}
	length := len(subject)
	m.subjects = ""
	m.subjectb = subject
	if length == 0 {
		subject = nullbyte // make first character addressable
	}
	subjectptr := (*C.char)(unsafe.Pointer(&subject[0]))
	return m.exec(subjectptr, length, flags)
}

// ExecString tries to match the specified subject string to
// the current pattern. It returns the raw pcre_exec error code.
func (m *Matcher) ExecString(subject string, flags uint32) int {
	if m.re.ptr == nil {
		panic("Matcher.ExecString: uninitialized")
	}
	length := len(subject)
	m.subjects = subject
	m.subjectb = nil
	if length == 0 {
		subject = "\000" // make first character addressable
	}
	// The following is a non-portable kludge to avoid a copy
	subjectptr := *(**C.char)(unsafe.Pointer(&subject))
	return m.exec(subjectptr, length, flags)
}

func (m *Matcher) exec(subjectptr *C.char, length int, flags uint32) int {
	rc := C.pcre2_match(m.re.ptr, C.PCRE2_SPTR(unsafe.Pointer(subjectptr)), C.PCRE2_SIZE(length),
		0, C.uint32_t(flags), m.mData.md, nil)
	return int(rc)
}

// Free releases the underlying C resources
func (m *Matcher) Free() {
	if m.mData != nil {
		runtime.SetFinalizer(m.mData, nil)
		finalizeMatchData(m.mData)
		m.mData = nil
	}
}

// HasError returns whether the matcher encountered an error condition.
func (m *Matcher) HasError() bool {
	return m.rc < 0 && m.rc != ERROR_PARTIAL && m.rc != ERROR_NOMATCH
}

// GetError returns the error if the matcher encountered an error condition.
func (m *Matcher) GetError() error {
	if matched(m.rc) {
		return nil
	}
	rawbytes := C.MY_pcre2_get_error_message(C.int(m.rc))
	msg := C.GoString((*C.char)(rawbytes))
	C.free(unsafe.Pointer(rawbytes))
	return &MatchError{
		ErrorNum: m.rc,
		Message:  msg,
	}
}

// matched checks the return code of a pattern match for success.
func matched(rc int) bool {
	if rc >= 0 || rc == ERROR_PARTIAL {
		return true
	}
	return false
}

// Matches returns true if a previous call to Matcher, MatcherString, Reset,
// ResetString, Match or MatchString succeeded.
func (m *Matcher) Matches() bool {
	return m.matches
}

// Partial returns true if a previous call to Matcher, MatcherString, Reset,
// ResetString, Match or MatchString found a partial match.
func (m *Matcher) Partial() bool {
	return m.partial
}

// Groups returns the number of groups in the current pattern.
func (m *Matcher) Groups() int {
	return m.groups
}

// Present returns true if the numbered capture group is present in the last
// match (performed by Matcher, MatcherString, Reset, ResetString,
// Match, or MatchString).  Group numbers start at 1.  A capture group
// can be present and match the empty string.
func (m *Matcher) Present(group int) bool {
	m.mData.ensureNotFreed()
	return m.mData.ovector[2*group] >= 0 && m.mData.ovector[2*group] != UNSET
}

// Group returns the numbered capture group of the last match (performed by
// Matcher, MatcherString, Reset, ResetString, Match, or MatchString).
// Group 0 is the part of the subject which matches the whole pattern;
// the first actual capture group is numbered 1.  Capture groups which
// are not present return a nil slice.
func (m *Matcher) Group(group int) []byte {
	m.mData.ensureNotFreed()
	start := m.mData.ovector[2*group]
	end := m.mData.ovector[2*group+1]
	if start >= 0 {
		if m.subjectb != nil {
			return m.subjectb[start:end]
		}
		return []byte(m.subjects[start:end])
	}
	return nil
}

// Extract returns a slice of byte slices for a single match.
// The first byte slice contains the complete match.
// Subsequent byte slices contain the captured groups.
// If there was no match then nil is returned.
func (m *Matcher) Extract() [][]byte {
	if !m.matches {
		return nil
	}
	m.mData.ensureNotFreed()
	extract := make([][]byte, m.groups+1)
	extract[0] = m.subjectb
	for i := 1; i <= m.groups; i++ {
		x0 := m.mData.ovector[2*i]
		x1 := m.mData.ovector[2*i+1]
		extract[i] = m.subjectb[x0:x1]
	}
	return extract
}

// ExtractString returns a slice of strings for a single match.
// The first string contains the complete match.
// Subsequent strings in the slice contain the captured groups.
// If there was no match then nil is returned.
func (m *Matcher) ExtractString() []string {
	if !m.matches {
		return nil
	}
	m.mData.ensureNotFreed()
	extract := make([]string, m.groups+1)
	extract[0] = m.subjects
	for i := 1; i <= m.groups; i++ {
		x0 := m.mData.ovector[2*i]
		x1 := m.mData.ovector[2*i+1]
		extract[i] = m.subjects[x0:x1]
	}
	return extract
}

// GroupIndices returns the numbered capture group positions of the last
// match (performed by Matcher, MatcherString, Reset, ResetString, Match,
// or MatchString). Group 0 is the part of the subject which matches
// the whole pattern; the first actual capture group is numbered 1.
// Capture groups which are not present return a nil slice.
func (m *Matcher) GroupIndices(group int) []int {
	m.mData.ensureNotFreed()
	start := m.mData.ovector[2*group]
	end := m.mData.ovector[2*group+1]
	if start >= 0 {
		return []int{int(start), int(end)}
	}
	return nil
}

// GroupString returns the numbered capture group as a string.  Group 0
// is the part of the subject which matches the whole pattern; the first
// actual capture group is numbered 1.  Capture groups which are not
// present return an empty string.
func (m *Matcher) GroupString(group int) string {
	m.mData.ensureNotFreed()
	start := m.mData.ovector[2*group]
	end := m.mData.ovector[2*group+1]
	if start >= 0 {
		if m.subjectb != nil {
			return string(m.subjectb[start:end])
		}
		return m.subjects[start:end]
	}
	return ""
}

// Index returns the start and end of the first match, if a previous
// call to Matcher, MatcherString, Reset, ResetString, Match or
// MatchString succeeded. loc[0] is the start and loc[1] is the end.
func (m *Matcher) Index() (loc []int) {
	if !m.matches {
		return nil
	}
	m.mData.ensureNotFreed()
	loc = []int{int(m.mData.ovector[0]), int(m.mData.ovector[1])}
	return
}

// name2index converts a group name to its group index number.
func (m *Matcher) name2index(name string) (int, error) {
	if m.re.ptr == nil {
		return 0, fmt.Errorf("Matcher.Named: uninitialized")
	}
	name1 := C.CString(name)
	defer C.free(unsafe.Pointer(name1))
	group := int(C.pcre2_substring_number_from_name(
		m.re.ptr, C.PCRE2_SPTR(unsafe.Pointer(name1))))
	if group < 0 {
		return group, fmt.Errorf("Matcher.Named: unknown name: " + name)
	}
	return group, nil
}

// Named returns the value of the named capture group.
// This is a nil slice if the capture group is not present.
// If the name does not refer to a group then error is non-nil.
func (m *Matcher) Named(group string) ([]byte, error) {
	groupNum, err := m.name2index(group)
	if err != nil {
		return []byte{}, err
	}
	return m.Group(groupNum), nil
}

// NamedString returns the value of the named capture group,
// or an empty string if the capture group is not present.
// If the name does not refer to a group then error is non-nil.
func (m *Matcher) NamedString(group string) (string, error) {
	groupNum, err := m.name2index(group)
	if err != nil {
		return "", err
	}
	return m.GroupString(groupNum), nil
}

// NamedPresent returns true if the named capture group is present.
// If the name does not refer to a group then error is non-nil.
func (m *Matcher) NamedPresent(group string) (bool, error) {
	groupNum, err := m.name2index(group)
	if err != nil {
		return false, err
	}
	return m.Present(groupNum), nil
}

// FindIndex returns the start and end of the first match,
// or nil if no match.  loc[0] is the start and loc[1] is the end.
func (re *Regexp) FindIndex(bytes []byte, flags uint32) (loc []int) {
	m := re.Matcher(bytes, flags)
	defer m.Free()
	if m.Matches() {
		loc = []int{int(m.mData.ovector[0]), int(m.mData.ovector[1])}
		return
	}
	return nil
}

// ReplaceAll returns a copy of a byte slice
// where all pattern matches are replaced by repl.
func (re *Regexp) ReplaceAll(bytes, repl []byte, flags uint32) []byte {
	m := re.Matcher(bytes, flags)
	defer m.Free()
	r := []byte{}
	for m.matches {
		r = append(append(r, bytes[:m.mData.ovector[0]]...), repl...)
		bytes = bytes[m.mData.ovector[1]:]
		m.Match(bytes, flags)
	}
	return append(r, bytes...)
}

// ReplaceAllString is equivalent to ReplaceAll with string return type.
func (re *Regexp) ReplaceAllString(in, repl string, flags uint32) string {
	return string(re.ReplaceAll([]byte(in), []byte(repl), flags))
}

// CompileError holds details about a compilation error,
// as returned by the Compile function. The offset is
// the byte position in the pattern string at which the
// error was detected.
type CompileError struct {
	Pattern string // The failed pattern
	Message string // The error message
	Offset  int    // Byte position of error
}

// Error converts a compile error to a string
func (e *CompileError) Error() string {
	return fmt.Sprintf("PCRE2 compilation failed at offset %d: %s", e.Offset, e.Message)
}

// JITError holds details about a JIT compilation error,
// as returned by the CompileJIT function.
type JITError struct {
	ErrorNum int // the error number, one of: ERROR_JIT_BADOPTION, ERROR_NOMEMORY
	Message  string
}

// Error converts a compile error to a string
func (e *JITError) Error() string {
	return fmt.Sprintf("JIT compilation failed: %s", e.Message)
}

// MatchError holds details about a matching error.
type MatchError struct {
	ErrorNum int // the error number
	Message  string
}

// Error converts a match error to a string
func (e *MatchError) Error() string {
	return fmt.Sprintf("Matching failed: %s", e.Message)
}
