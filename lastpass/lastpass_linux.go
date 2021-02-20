// Package lastpass is an `lpass` based credential helper. Secrets are
// stored in the "$LASTPASS_FOLDER" as individual entries containing
// a URL, a user and a password.
package lastpass

import (
  "bufio"
  "bytes"
  "errors"
  "fmt"
  "net/url"
  "os"
  "os/exec"
  "path"
  "strings"
  "sync"

  "github.com/docker/docker-credential-helpers/credentials"
)

// LASTPASS_FOLDER is the folder at the root of LastPass account
// containing all the credentials managed by this app.
const LASTPASS_FOLDER = "Docker Credentials"

// LastPass is an `lpass`-backed secret store
type LastPass struct{}

// initializationMutex is held while initializing so that only one 'lpass'
// round-tripping is done to check lpass is usable.
var initializationMutex sync.Mutex
var lpassInitialized bool

func runLastPassHelper(stdinContent string, args ...string) (string, error) {
  var stdout, stderr bytes.Buffer
  cmd := exec.Command("lpass", args...)
  cmd.Stdin = strings.NewReader(stdinContent)
  cmd.Stdout = &stdout
  cmd.Stderr = &stderr

  err := cmd.Run()
  if err != nil {
    return "", fmt.Errorf("%s: %s", err, stderr.String())
  }

  // trim newlines; lpass includes a newline at the end of its output
  return strings.TrimRight(stdout.String(), "\n"), nil
}

func checkInitialized() error {
  initializationMutex.Lock()
  defer initializationMutex.Unlock()
  if lpassInitialized {
    return nil
  }
  _, err := runLastPassHelper("", "status", "--quiet")
  if err != nil {
    fmt.Print("Enter your LastPass username: ")
    reader := bufio.NewReader(os.Stdin)
    lpassUsername, _ := reader.ReadString('\n')

    cmd := exec.Command("lpass", "login", lpassUsername)
    err := cmd.Run()
    if err != nil {
      return fmt.Errorf("Failed to log into `lpass`; " +
                        "try running `lpass login %s` yourself.",
                        lpassUsername)
    }
  }
  _, err = runLastPassHelper("", "status", "--quiet")
  if err != nil {
    return fmt.Errorf("lpass not initialized: %v", err)
  }
  lpassInitialized = true
  return nil
}

func (s LastPass) runLastPass(stdinContent string, args ...string) (string, error) {
  if err := checkInitialized(); err != nil {
    return "", err
  }
  return runLastPassHelper(stdinContent, args...)
}

func domainInURL(serverURL string) (string, error) {
  url, err := url.Parse(serverURL)
  if err != nil {
    return "", err
  }
  return url.Hostname(), nil
}

// Get returns the username and secret to use for a given registry server URL.
func (s LastPass) Get(serverURL string) (string, string, error) {
  if serverURL == "" {
    return "", "", errors.New("missing server url")
  }

  domain, err := domainInURL(serverURL)
  if err != nil {
    return "", "", err
  }

  username, err := s.runLastPass("", "show", "--user", path.Join(LASTPASS_FOLDER, domain))
  if err != nil {
    return "", "", err
  }

  secret, err := s.runLastPass("", "show", "--pass", path.Join(LASTPASS_FOLDER, domain))
  if err != nil {
    return "", "", err
  }

  return username, secret, err
}

// Add adds new credentials to the store.
func (s LastPass) Add(creds *credentials.Credentials) error {
  if creds == nil {
    return errors.New("missing credentials")
  }

  domain, err := domainInURL(creds.ServerURL)
  if err != nil {
    return err
  }

  details := fmt.Sprintf("URL: %s\nUsername: %s\nPassword: %s\n",
                         creds.ServerURL, creds.Username, creds.Secret)

  // If the entry already exists, update it instead of creating another one
   _, _, err = s.Get(creds.ServerURL)
  if err != nil {
    _, err := s.runLastPass(details, "edit", "--non-interactive", path.Join(LASTPASS_FOLDER, domain))
    return err
  }

  _, err = s.runLastPass(details, "add", "--non-interactive", path.Join(LASTPASS_FOLDER, domain))
  return err
}

// Delete removes credentials from the store.
func (s LastPass) Delete(serverURL string) error {
  if serverURL == "" {
    return errors.New("missing server url")
  }

  domain, err := domainInURL(serverURL)
  if err != nil {
    return err
  }

  //FIXME: might need to get the id first, and then delete the id
  _, err = s.runLastPass("", "rm", path.Join(LASTPASS_FOLDER, domain))
  return err
}

// List returns the stored URLs and corresponding usernames for a given credentials label
func (s LastPass) List() (map[string]string, error) {
  output, err := s.runLastPass("", "ls", "--format", "%ai", LASTPASS_FOLDER)
  if err != nil {
    return nil, err
  }

  entries := strings.Split(output, "\n")

  resp := map[string]string{}

  for _, entry := range entries {
    entryID := string(entry)

    serverURL, err := s.runLastPass("", "show", "--url", entryID)
    if err != nil {
      return nil, err
    }

    username, err := s.runLastPass("", "show", "--user", entryID)
    if err != nil {
      return nil, err
    }

    resp[string(serverURL)] = username
  }

  return resp, nil
}
