package models

import "time"

// SecurityEvent stores a persisted firewall decision or observation.
type SecurityEvent struct {
	ID        uint       `gorm:"primarykey" json:"id"`
	CreatedAt time.Time  `gorm:"index" json:"created_at"`
	Host      string     `gorm:"index" json:"host"`
	IP        string     `gorm:"index" json:"ip"`
	Method    string     `json:"method"`
	Path      string     `json:"path"`
	Reason    string     `json:"reason"`
	Weight    int        `json:"weight"`
	Observed  bool       `json:"observed"`
	Action    string     `gorm:"index" json:"action"`
	JailUntil *time.Time `json:"jail_until,omitempty"`
	Country   string     `json:"country"`
	City      string     `json:"city"`
	ASN       string     `json:"asn"`
}
