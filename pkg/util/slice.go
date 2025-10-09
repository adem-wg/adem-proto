package util

func Contains[T comparable](slice []T, v T) bool {
	for _, elem := range slice {
		if elem == v {
			return true
		}
	}
	return false
}

func Insert[S ~[]E, E any](s S, i int, v E) S {
	if i < len(s) {
		s[i] = v
		return s
	} else {
		s = append(s, make([]E, i - len(s))...)
		return append(s, v)
	}
}
