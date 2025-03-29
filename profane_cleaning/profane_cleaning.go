package cleaning

import (
	"slices"
	"strings"
)

func Profanecleaning(s string) string {
	profane := []string{"kerfuffle", "sharbert", "fornax"}
	slice := strings.Split(s, " ")
	for i := 0; i < len(slice); i++ {
		lowered := strings.ToLower(slice[i])
		if slices.Contains(profane, lowered) {
			slice[i] = "****"
		}
	}
	cleaned := strings.Join(slice, " ")
	return cleaned
}
