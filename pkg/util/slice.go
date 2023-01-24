package util

func Contains[T comparable](slice []T, v T) bool {
	for _, elem := range slice {
		if elem == v {
			return true
		}
	}
	return false
}
