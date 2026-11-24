package nosurf

import (
	"fmt"
	"net/http"
	pathModule "path"
	"regexp"
)

// Checks if the given request is exempt from CSRF checks.
// It checks the ExemptFunc first, then the exact paths,
// then the globs and finally the regexps. All path-based
// checks use the same normalized path.
func (h *CSRFHandler) IsExempt(r *http.Request) bool {
	if h.exemptFunc != nil && h.exemptFunc(r) {
		return true
	}

	path := normalizeExemptPath(r.URL.Path)
	if sContains(h.exemptPaths, path) {
		return true
	}

	// then the globs
	for _, glob := range h.exemptGlobs {
		matched, err := pathModule.Match(glob, path)
		if matched && err == nil {
			return true
		}
	}

	// finally, the regexps
	for _, re := range h.exemptRegexps {
		if re.MatchString(path) {
			return true
		}
	}

	return false
}

// normalizeExemptPath returns the single path representation shared by all
// path-based exemption checks. net/http has already percent-decoded URL.Path,
// so only dot segments and duplicate slashes need to be resolved here.
func normalizeExemptPath(path string) string {
	if path == "" {
		return ""
	}

	hasTrailingSlash := len(path) > 1 && path[len(path)-1] == '/'
	path = pathModule.Clean(path)
	if hasTrailingSlash && path != "/" {
		path += "/"
	}

	return path
}

// Exempts an exact path from CSRF checks
// With this (and other Exempt* methods)
// you should take note that Go's paths
// include a leading slash.
func (h *CSRFHandler) ExemptPath(path string) {
	h.exemptPaths = append(h.exemptPaths, path)
}

// A variadic argument version of ExemptPath()
func (h *CSRFHandler) ExemptPaths(paths ...string) {
	h.exemptPaths = append(h.exemptPaths, paths...)
}

// Exempts URLs that match the specified glob pattern
// (as used by filepath.Match()) from CSRF checks
//
// Note that ExemptGlob() is unable to detect syntax errors,
// because it doesn't have a path to check it against
// and filepath.Match() doesn't report an error
// if the path is empty.
// If we find a way to check the syntax, ExemptGlob
// MIGHT PANIC on a syntax error in the future.
// ALWAYS check your globs for syntax errors.
func (h *CSRFHandler) ExemptGlob(pattern string) {
	h.exemptGlobs = append(h.exemptGlobs, pattern)
}

// A variadic argument version of ExemptGlob()
func (h *CSRFHandler) ExemptGlobs(patterns ...string) {
	h.exemptGlobs = append(h.exemptGlobs, patterns...)
}

// Accepts a regular expression string or a compiled *regexp.Regexp
// and exempts URLs that match it from CSRF checks.
//
// If the given argument is neither of the accepted values,
// or the given string fails to compile, ExemptRegexp() panics.
func (h *CSRFHandler) ExemptRegexp(re interface{}) {
	var compiled *regexp.Regexp

	switch re := re.(type) {
	case string:
		compiled = regexp.MustCompile(re)
	case *regexp.Regexp:
		compiled = re
	default:
		err := fmt.Errorf("%T is not a valid type for ExemptRegexp()", re)
		panic(err)
	}

	h.exemptRegexps = append(h.exemptRegexps, compiled)
}

// A variadic argument version of ExemptRegexp()
func (h *CSRFHandler) ExemptRegexps(res ...interface{}) {
	for _, v := range res {
		h.ExemptRegexp(v)
	}
}

func (h *CSRFHandler) ExemptFunc(fn func(r *http.Request) bool) {
	h.exemptFunc = fn
}
