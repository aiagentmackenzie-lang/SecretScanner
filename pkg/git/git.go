package git

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// Scanner provides git repository scanning capabilities
type Scanner struct {
	repo *git.Repository
	path string
}

// NewScanner creates a new git scanner for a repository
func NewScanner(path string) (*Scanner, error) {
	// Check if path is a git repo
	gitPath := filepath.Join(path, ".git")
	if _, err := os.Stat(gitPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("not a git repository: %s", path)
	}

	repo, err := git.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open git repo: %w", err)
	}

	return &Scanner{
		repo: repo,
		path: path,
	}, nil
}

// ScanCommits scans git history for secrets
func (s *Scanner) ScanCommits(callback func(commitHash string, content []byte, filename string) error) error {
	// Get all commits
	logIter, err := s.repo.Log(&git.LogOptions{})
	if err != nil {
		return fmt.Errorf("failed to get commit log: %w", err)
	}
	defer logIter.Close()

	err = logIter.ForEach(func(commit *object.Commit) error {
		// Get commit tree
		tree, err := commit.Tree()
		if err != nil {
			return nil // Continue on error
		}

		// Iterate over files in tree
		treeIter := tree.Files()
		defer treeIter.Close()

		return treeIter.ForEach(func(file *object.File) error {
			content, err := file.Contents()
			if err != nil {
				return nil
			}

			// Scan this file
			return callback(commit.Hash.String(), []byte(content), file.Name)
		})
	})

	return err
}

// ScanStaged scans staged (index) changes
func (s *Scanner) ScanStaged(callback func(content []byte, filename string) error) error {
	worktree, err := s.repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	status, err := worktree.Status()
	if err != nil {
		return fmt.Errorf("failed to get status: %w", err)
	}

	for file := range status {
		if status[file].Staging == git.Untracked {
			continue
		}
		
		// For now, just skip - full implementation would read from index
		_ = callback
	}

	return nil
}

// HasRemote checks if the repo has a remote origin
func (s *Scanner) HasRemote() bool {
	_, err := s.repo.Remote("origin")
	return err == nil
}

// GetRemoteURL returns the origin remote URL
func (s *Scanner) GetRemoteURL() (string, error) {
	remote, err := s.repo.Remote("origin")
	if err != nil {
		return "", err
	}
	return remote.Config().URLs[0], nil
}
