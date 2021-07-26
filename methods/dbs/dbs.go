package dbs

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/SantoshSah/user-service-sample/types"
	"github.com/allegro/bigcache/v3"
	redis "github.com/go-redis/redis/v8"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/plugin/dbresolver"
)

var (
	// RedisClient: redis client for connecting to redis
	RedisClient *redis.Client
	// PostgresDB: postgresDB client for connecting to CRDB
	PostgresDB *gorm.DB
	// Cache Manager
	Cache, _ = bigcache.NewBigCache(bigcache.DefaultConfig(time.Minute * 60 * 24 * 365 * 10))
)

// GetEnv accepts the ENV as key and a default string
// If the lookup returns false then it uses the default string else it leverages the value set in ENV variable
func GetEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}

	log.Println("Setting default values for ENV variable " + key)
	return fallback
}

// ConnectPostgresDB returns a postgres client
func ConnectPostgresDB() *gorm.DB {
	tenants := []string{"tenant1", "tenant_master", "tenant2"}
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold: time.Second, // Slow SQL threshold
			LogLevel:      logger.Info, // Log level
			Colorful:      true,        // Disable color
		},
	)

	// Setup CRDB
	crdbConnStrTenant1 := os.Getenv("CRDB_CONNECTION_STRING_TENANT1")
	dns_tenant1 := strings.Replace(crdbConnStrTenant1, "\"", "", -1)
	PostgresDB, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  dns_tenant1,
		PreferSimpleProtocol: true,
	}), &gorm.Config{
		Logger: newLogger,
	})

	//SkipDefaultTransaction: true,

	crdbConnStrMASTER := os.Getenv("CRDB_CONNECTION_STRING_MASTER")
	dns_master := strings.Replace(crdbConnStrMASTER, "\"", "", -1)

	crdbConnStrABC := os.Getenv("CRDB_CONNECTION_STRING_ABC")
	dns_abc := strings.Replace(crdbConnStrABC, "\"", "", -1)

	PostgresDB.Use(dbresolver.
		Register(dbresolver.Config{
			Sources: []gorm.Dialector{postgres.New(postgres.Config{
				DSN:                  dns_master,
				PreferSimpleProtocol: true,
			})},
		}, tenants[1]).
		Register(dbresolver.Config{
			Sources: []gorm.Dialector{postgres.New(postgres.Config{
				DSN:                  dns_abc,
				PreferSimpleProtocol: true,
			})},
		}, tenants[2]))

	if err != nil {
		log.Println("Error initialising crdb:", dns_tenant1, err)
	}

	// Migrate the schema
	// Reset cache
	resetErr := Cache.Reset()
	if resetErr == nil {
		for _, tenant := range tenants {
			PostgresDB.
				Clauses(dbresolver.Use(tenant)).
				AutoMigrate(
					&types.User{},
				)
		}
	}

	return PostgresDB
}

// ConnectRedisDB returns a redis client
func ConnectRedisDB() *redis.Client {
	redisSentinelHost := GetEnv("REDIS_SENTINEL_HOST", "0.0.0.0")
	redisSentinelPort := GetEnv("REDIS_SENTINEL_PORT", "26379")
	redisPassword := GetEnv("REDIS_PASSWORD", "secret")
	masterName := GetEnv("REDIS_SENTINEL_MASTER_NAME", "mymaster")
	sentinelAddrs := fmt.Sprintf("%s:%s", redisSentinelHost, redisSentinelPort)

	RedisClient = redis.NewFailoverClient(&redis.FailoverOptions{
		MasterName:       masterName,
		SentinelAddrs:    []string{sentinelAddrs},
		Password:         redisPassword,
		SentinelPassword: redisPassword,
		DB:               0,
	})

	pong, err := RedisClient.Ping(RedisClient.Context()).Result()
	log.Println(fmt.Sprintf("Reply from Redis %s", pong))
	if err != nil {
		log.Println(fmt.Sprintf("Failed connecting to redis db %s", err.Error()))
		os.Exit(1)
	}
	log.Println("Successfully connected to redis database")

	return RedisClient
}
