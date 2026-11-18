// Package auth holds the signed-in identity stored in a ghook session.
package auth

// Identity is the signed-in Google user on a session cookie.
type Identity struct {
	Subject  string
	Email    string
	Name     string
	Username string
}

// Display is a short label: username, else email, else name, else the subject.
func (i Identity) Display() string {
	switch {
	case i.Username != "":
		return i.Username
	case i.Email != "":
		return i.Email
	case i.Name != "":
		return i.Name
	}
	return i.Subject
}
