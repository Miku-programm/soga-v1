package vmess

type ServiceOption func(service *Service[string])

// ServiceWithReducedMemory uses the documented 25-second MD5 clock window.
func ServiceWithReducedMemory(enabled bool) ServiceOption {
	return func(service *Service[string]) { service.reducedMemory = enabled }
}

type AuthenticationCache interface {
	Candidate(string) string
	Remember(string, string)
}

func ServiceWithAuthenticationCache(cache AuthenticationCache) ServiceOption {
	return func(service *Service[string]) { service.authCache = cache }
}

// ServiceWithAuthMode is a reconstruction extension; caller validates the mode.
func ServiceWithAuthMode(mode string) ServiceOption {
	return func(service *Service[string]) { service.authMode = mode }
}

func ServiceWithTimeFunc(timeFunc TimeFunc) ServiceOption {
	return func(service *Service[string]) {
		service.time = timeFunc
	}
}

func ServiceWithDisableHeaderProtection() ServiceOption {
	return func(service *Service[string]) {
		service.disableHeaderProtect = true
	}
}
