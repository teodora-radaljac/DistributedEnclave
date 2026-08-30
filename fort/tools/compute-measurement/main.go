// compute-measurement calculates the expected SEV-SNP launch measurement for
// a QEMU CVM, given the OVMF firmware binary, kernel, initrd, and cmdline.
// The output can be fed directly into FORT_EXPECTED_MEASUREMENT on the
// verifier server.
//
// Usage:
//
//	compute-measurement [flags]
//
// Example:
//
//	compute-measurement \
//	    -ovmf   /path/to/OVMF.amdsev.fd \
//	    -kernel /path/to/bzImage \
//	    -initrd /path/to/rootfs.cpio.gz \
//	    -append "console=ttyS0 root=/dev/ram0 rw verifier_ip=192.168.100.1 verifier_port=9443 atls_snp_attestation=true"
//
// Pipe measurement into the server:
//
//	FORT_EXPECTED_MEASUREMENT=$(compute-measurement -kernel ... -initrd ...) ./server
//
// The kernel cmdline (-append) must be identical across all workers.
// If it contains per-worker values (e.g. ray_worker_id), those workers will
// produce different MEASUREMENT values and attestation will fail.
// Remove such parameters from the QEMU -append line and derive them from the
// MAC address inside the VM instead (see network_up.sh and ray_init.sh).
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/virtee/sev-snp-measure-go/cpuid"
	"github.com/virtee/sev-snp-measure-go/gctx"
	"github.com/virtee/sev-snp-measure-go/guest"
	"github.com/virtee/sev-snp-measure-go/ovmf"
	"github.com/virtee/sev-snp-measure-go/vmsa"
	"github.com/virtee/sev-snp-measure-go/vmmtypes"
)

// GUIDs for the kernel hashes table (from QEMU hw/i386/x86-common.c)
const (
	tableHeaderGUID = "9438d606-4f22-4cc9-b479-a793d411fd21"
	kernelHashGUID  = "4de79437-abd2-427f-b835-d5b172d2045b"
	initrdHashGUID  = "44baf731-3a2f-4bd7-9af1-41e29169781d"
	cmdlineHashGUID = "97d02dd8-bd20-4c94-aa78-e7714d36ab2a"
)

// guidLE converts a UUID string to the little-endian byte representation
// used by QEMU and OVMF (first 3 groups reversed, last 2 groups unchanged).
func guidLE(s string) [16]byte {
	clean := strings.ReplaceAll(s, "-", "")
	b, _ := hex.DecodeString(clean)
	var id [16]byte
	copy(id[:], b)
	return ovmf.LittleEndianBytes(id)
}

// hashEntry builds a 50-byte kernel hash table entry:
//
//	GUID (16 bytes LE) | entry_size (2 bytes LE) | SHA-256 hash (32 bytes)
//
// If data is nil, the hash field is all zeros (entry still present).
func hashEntry(guidStr string, data []byte) []byte {
	const entrySize = 16 + 2 + 32 // 50 bytes
	g := guidLE(guidStr)
	entry := make([]byte, entrySize)
	copy(entry[:16], g[:])
	binary.LittleEndian.PutUint16(entry[16:18], entrySize)
	if len(data) > 0 {
		h := sha256.Sum256(data)
		copy(entry[18:], h[:])
	}
	return entry
}

// kernelHashesPage builds the 4096-byte page that QEMU writes to the
// SNPKernelHashes GPA when kernel-hashes=on is set on the sev-snp-guest object.
//
// Layout (entries packed at the END of the page, reading left-to-right):
//
//	[ padding: zeros ] [ cmdline entry 50B ] [ initrd entry 50B ] [ kernel entry 50B ]
//	[ table_size 2B ] [ table_guid 16B ]
//
// initrdData and cmdline may be nil/empty; those entries get zero hashes.
func kernelHashesPage(kernelData, initrdData []byte, cmdline string, pageSize int) ([]byte, error) {
	const entrySize = 50

	// Cmdline: QEMU hashes (cmdline string + NUL terminator).
	var cmdlineBytes []byte
	if cmdline != "" {
		cmdlineBytes = []byte(cmdline + "\x00")
	}
	cmdlineEntry := hashEntry(cmdlineHashGUID, cmdlineBytes)
	initrdEntry := hashEntry(initrdHashGUID, initrdData)
	kernelEntry := hashEntry(kernelHashGUID, kernelData)

	// Order from QEMU: cmdline, initrd, kernel (lowest to highest address in the blob)
	entries := make([]byte, 0, 3*entrySize)
	entries = append(entries, cmdlineEntry...)
	entries = append(entries, initrdEntry...)
	entries = append(entries, kernelEntry...)

	// Table footer: total_size (2 bytes) + header GUID (16 bytes)
	// total_size covers: entries + size field + GUID = 150 + 2 + 16 = 168
	tableSize := uint16(len(entries) + 2 + 16)
	sizeBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(sizeBuf, tableSize)
	g := guidLE(tableHeaderGUID)

	blob := make([]byte, 0, len(entries)+18)
	blob = append(blob, entries...)
	blob = append(blob, sizeBuf...)
	blob = append(blob, g[:]...)

	if len(blob) > pageSize {
		return nil, fmt.Errorf("kernel hashes blob (%d B) exceeds page size (%d B)", len(blob), pageSize)
	}
	page := make([]byte, pageSize)
	copy(page[pageSize-len(blob):], blob)
	return page, nil
}

// launchDigest replicates the guest.LaunchDigestFromMetadataWrapper logic but
// adds handling for the SNPKernelHashes section (type 0x10), which the upstream
// library does not implement.
func launchDigest(
	items []ovmf.MetadataSection,
	resetEIP uint32,
	ovmfHash []byte,
	guestFeatures uint64,
	vcpuCount int,
	vcpuType string,
	kernelData, initrdData []byte,
	cmdline string,
) ([]byte, error) {
	guestCtx := gctx.New(ovmfHash)

	for _, desc := range items {
		st := ovmf.SectionType(desc.SectionTypeInt)
		gpa := uint64(desc.GPA)
		size := int(desc.Size)

		var err error
		switch st {
		case ovmf.SNPSECMEM:
			err = guestCtx.UpdateZeroPages(gpa, size)
		case ovmf.SNPSecrets:
			err = guestCtx.UpdateSecretsPage(gpa)
		case ovmf.CPUID:
			err = guestCtx.UpdateCpuidPage(gpa)
		case ovmf.SVSM_CAA:
			err = guestCtx.UpdateZeroPages(gpa, size)
		case ovmf.SNPKernelHashes:
			// Measured as a normal data page (type 0x01).
			// Content is the kernel hashes table if kernel-hashes=on was used;
			// all zeros otherwise (QEMU didn't write anything to this GPA).
			var page []byte
			if len(kernelData) > 0 {
				page, err = kernelHashesPage(kernelData, initrdData, cmdline, size)
				if err != nil {
					return nil, err
				}
			} else {
				page = make([]byte, size)
			}
			err = guestCtx.UpdateNormalPages(gpa, page)
		default:
			return nil, fmt.Errorf("unhandled OVMF metadata section type %d at GPA 0x%x", desc.SectionTypeInt, gpa)
		}
		if err != nil {
			return nil, fmt.Errorf("section type %d at GPA 0x%x: %w", desc.SectionTypeInt, gpa, err)
		}
	}

	cpuSig, ok := cpuid.CpuSigs[vcpuType]
	if !ok {
		return nil, fmt.Errorf("unknown vcpu-type %q; valid types: EPYC, EPYC-Milan, EPYC-Genoa, …", vcpuType)
	}

	vmsaObj, err := vmsa.New(resetEIP, guestFeatures, uint64(cpuSig), vmmtypes.QEMU)
	if err != nil {
		return nil, fmt.Errorf("build VMSA: %w", err)
	}
	pages, err := vmsaObj.Pages(vcpuCount)
	if err != nil {
		return nil, fmt.Errorf("VMSA pages: %w", err)
	}
	for _, p := range pages {
		if err := guestCtx.UpdateVmsaPage(p); err != nil {
			return nil, fmt.Errorf("update VMSA page: %w", err)
		}
	}
	return guestCtx.LD(), nil
}

func main() {
	ovmfPath := flag.String("ovmf", "",
		"Path to AMD SEV OVMF firmware binary (required)")
	kernelPath := flag.String("kernel", "",
		"Path to bzImage kernel binary (required for kernel-hashes measurement)")
	initrdPath := flag.String("initrd", "",
		"Path to initramfs (rootfs.cpio.gz)")
	appendStr := flag.String("append", "",
		"Kernel cmdline string (must be identical across all workers; NUL-terminated before hashing)")
	vcpus := flag.Int("vcpus", 2,
		"Number of vCPUs — must match -smp in the QEMU command")
	vcpuType := flag.String("vcpu-type", "EPYC-v4",
		"QEMU CPU type — must match -cpu in the QEMU command")
	guestFeaturesStr := flag.String("guest-features", "0x1",
		"Guest features bitmask (hex); 0x1 = SNP only, 0x21 = SNP+restricted-injection")
	flag.Parse()

	guestFeatures, err := strconv.ParseUint(*guestFeaturesStr, 0, 64)
	if err != nil {
		log.Fatalf("invalid -guest-features %q: %v", *guestFeaturesStr, err)
	}
	if *ovmfPath == "" {
		log.Fatalf("-ovmf is required")
	}

	ovmfObj, err := ovmf.New(*ovmfPath)
	if err != nil {
		log.Fatalf("load OVMF %s: %v", *ovmfPath, err)
	}

	ovmfHash, err := guest.OVMFHash(ovmfObj)
	if err != nil {
		log.Fatalf("compute OVMF hash: %v", err)
	}

	resetEIP, err := ovmfObj.SevESResetEIP()
	if err != nil {
		log.Fatalf("read SEV-ES reset EIP: %v", err)
	}

	var kernelData, initrdData []byte
	if *kernelPath != "" {
		kernelData, err = os.ReadFile(*kernelPath)
		if err != nil {
			log.Fatalf("read kernel %s: %v", *kernelPath, err)
		}
		fmt.Fprintf(os.Stderr, "kernel:         %s (%d bytes)\n", *kernelPath, len(kernelData))
	}
	if *initrdPath != "" {
		initrdData, err = os.ReadFile(*initrdPath)
		if err != nil {
			log.Fatalf("read initrd %s: %v", *initrdPath, err)
		}
		fmt.Fprintf(os.Stderr, "initrd:         %s (%d bytes)\n", *initrdPath, len(initrdData))
	}
	if *appendStr != "" {
		fmt.Fprintf(os.Stderr, "append:         %s\n", *appendStr)
	}

	if len(kernelData) == 0 && (*initrdPath != "" || *appendStr != "") {
		log.Fatalf("-initrd and -append require -kernel")
	}

	measurement, err := launchDigest(
		ovmfObj.MetadataItems(),
		resetEIP,
		ovmfHash,
		guestFeatures,
		*vcpus,
		*vcpuType,
		kernelData,
		initrdData,
		*appendStr,
	)
	if err != nil {
		log.Fatalf("compute launch digest: %v", err)
	}
	if len(measurement) != 48 {
		log.Fatalf("unexpected measurement length %d (want 48)", len(measurement))
	}

	fmt.Println(hex.EncodeToString(measurement))

	fmt.Fprintf(os.Stderr, "ovmf:           %s\n", *ovmfPath)
	fmt.Fprintf(os.Stderr, "vcpus:          %d\n", *vcpus)
	fmt.Fprintf(os.Stderr, "vcpu-type:      %s\n", *vcpuType)
	fmt.Fprintf(os.Stderr, "guest-features: %s\n", *guestFeaturesStr)
	fmt.Fprintf(os.Stderr, "measurement:    %s\n", hex.EncodeToString(measurement))
}
