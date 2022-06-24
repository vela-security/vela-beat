package track

func protective(name string) bool {
	n := len(name)
	if n == 0 {
		return false
	}

	for i := 0; i < n; i++ {
		ch := name[i]
		switch ch {
		case '&', ';', '$', '(', ')', '`', '|', '=', '%':
			return false
		}
	}

	return true
}
