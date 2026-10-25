package checks

import "os"

// Windows has no inode in os.FileInfo; rotation is caught by the size check.
func fileID(os.FileInfo) uint64 { return 0 }
