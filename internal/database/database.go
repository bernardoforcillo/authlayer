package database

import (
	"time"

	"github.com/bernardoforcillo/authlayer/internal/config"
	"github.com/bernardoforcillo/authlayer/internal/model"

	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// New opens a GORM PostgreSQL connection with sensible defaults.
func New(cfg *config.Config, log *zap.Logger) (*gorm.DB, error) {
	logLevel := logger.Silent
	if cfg.Environment == "development" {
		logLevel = logger.Info
	}

	db, err := gorm.Open(postgres.Open(cfg.DatabaseURL), &gorm.Config{
		Logger:                 logger.Default.LogMode(logLevel),
		SkipDefaultTransaction: true,
	})
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	log.Info("connected to database")
	return db, nil
}

// Migrate runs auto-migration for all models.
func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&model.User{},
		&model.Account{},
		&model.Session{},
		&model.APIKey{},
		&model.Organization{},
		&model.Team{},
		&model.Role{},
		&model.Permission{},
		&model.RolePermission{},
		&model.OrganizationMember{},
		&model.TeamMember{},
		&model.Invitation{},
		&model.ServiceAccount{},
		&model.ServiceAccountKey{},
		&model.ServiceAccountRole{},
	)
}
