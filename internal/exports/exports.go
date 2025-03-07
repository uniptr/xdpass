package exports

import "sync"

func registerAPI[T any](lock *sync.RWMutex, m map[string]T, ifaceName string, api T) {
	lock.Lock()
	defer lock.Unlock()
	m[ifaceName] = api
}

func unregisterAPI[T any](lock *sync.RWMutex, m map[string]T, ifaceName string) {
	lock.Lock()
	defer lock.Unlock()
	delete(m, ifaceName)
}

func getAPI[T any](lock *sync.RWMutex, m map[string]T, ifaceName string) (T, bool) {
	lock.RLock()
	defer lock.RUnlock()
	api, ok := m[ifaceName]
	return api, ok
}

func getAllAPIs[T any](lock *sync.RWMutex, m map[string]T) map[string]T {
	lock.RLock()
	defer lock.RUnlock()

	apis := make(map[string]T)
	for ifaceName, api := range m {
		apis[ifaceName] = api
	}
	return apis
}
