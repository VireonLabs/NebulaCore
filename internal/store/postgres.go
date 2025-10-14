package store

import (
	"context"
	"database/sql"
	"os"
	"strconv"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type ProviderAccount struct {
	ID        uint       `gorm:"primaryKey"`
	Provider  string     `gorm:"uniqueIndex:idx_provider_name;size:100;not null"`
	Name      string     `gorm:"uniqueIndex:idx_provider_name;size:150;not null"`
	Config    string     `gorm:"type:text"`
	QuotaJSON string     `gorm:"type:text"`
	Enabled   bool       `gorm:"default:true"`
	ExpiresAt *time.Time
	CreatedAt time.Time  `gorm:"autoCreateTime"`
	UpdatedAt time.Time  `gorm:"autoUpdateTime"`
}

type Agent struct {
	ID         uint      `gorm:"primaryKey"`
	AgentID    string    `gorm:"uniqueIndex;size:128;not null"`
	Address    string    `gorm:"size:256"`
	Capacity   int       `gorm:"default:1"`
	Labels     string    `gorm:"type:text"`
	LastSeen   time.Time `gorm:"index:idx_agent_lastseen"`
	Status     string    `gorm:"index;size:50"`
	CreatedAt  time.Time `gorm:"autoCreateTime"`
	UpdatedAt  time.Time `gorm:"autoUpdateTime"`
}

type Job struct {
	ID         uint      `gorm:"primaryKey"`
	Type       string    `gorm:"size:100;index"`
	Payload    string    `gorm:"type:text"`
	AssignedTo *uint
	Status     string    `gorm:"size:50;index:idx_job_status_priority,priority:1;default:'pending'"`
	Attempts   int       `gorm:"default:0"`
	Priority   int       `gorm:"index:idx_job_status_priority,priority:2;default:0"`
	CreatedAt  time.Time `gorm:"autoCreateTime"`
	UpdatedAt  time.Time `gorm:"autoUpdateTime"`
}

func getenvInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return n
	}
	return def
}

func NewPostgres(dsn string) (*gorm.DB, error) {
	if dsn == "" {
		return nil, &dsnError{"empty dsn"}
	}

	var db *gorm.DB
	var err error
	retries := 3
	backoff := time.Second

	for i := 0; i < retries; i++ {
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err != nil {
			time.Sleep(backoff)
			backoff *= 2
			continue
		}

		sqlDB, err := db.DB()
		if err != nil {
			_ = sqlDB.Close()
			time.Sleep(backoff)
			backoff *= 2
			continue
		}

		maxOpen := getenvInt("NEB_DB_MAX_OPEN_CONNS", 50)
		maxIdle := getenvInt("NEB_DB_MAX_IDLE_CONNS", 25)
		maxLifetimeMin := getenvInt("NEB_DB_CONN_MAX_LIFETIME_MIN", 60)

		sqlDB.SetMaxOpenConns(maxOpen)
		sqlDB.SetMaxIdleConns(maxIdle)
		sqlDB.SetConnMaxLifetime(time.Duration(maxLifetimeMin) * time.Minute)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = sqlDB.PingContext(ctx)
		cancel()
		if err != nil {
			_ = sqlDB.Close()
			time.Sleep(backoff)
			backoff *= 2
			continue
		}

		if err := db.Exec("SET TIME ZONE 'UTC'").Error; err != nil {
			_ = sqlDB.Close()
			time.Sleep(backoff)
			backoff *= 2
			continue
		}

		if err := db.AutoMigrate(&ProviderAccount{}, &Agent{}, &Job{}); err != nil {
			_ = sqlDB.Close()
			return nil, err
		}

		return db, nil
	}

	return nil, err
}

func CloseDB(db *gorm.DB) error {
	if db == nil {
		return nil
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

type dsnError struct{ s string }

func (e *dsnError) Error() string { return e.s }