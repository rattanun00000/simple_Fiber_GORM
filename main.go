package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var jwtSecretKey = []byte("your-secret-key") // ในระบบจริงควรใช้ environment variable

const (
	host     = "localhost"
	port     = 5432
	user     = "myuser"
	password = "mypassword"
	dbname   = "mydatabase"
)

func authRequired(c *fiber.Ctx) error {
	cookie := c.Cookies("jwt")

	if cookie == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "กรุณาเข้าสู่ระบบ",
		})
	}

	// เปลี่ยนเป็น RegisteredClaims
	token, err := jwt.ParseWithClaims(cookie, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecretKey, nil
	})

	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Token ไม่ถูกต้อง",
		})
	}

	if !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Token หมดอายุ",
		})
	}

	// ดึง claims และเก็บ user ID ใน context
	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok {
		c.Locals("userID", claims.Subject)
	}

	return c.Next()
}

func main() {
	// Configure your PostgreSQL database details here
	dsn := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold: time.Second,
			LogLevel:      logger.Info,
			Colorful:      true,
		},
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: newLogger,
	})

	if err != nil {
		panic("failed to connect to database")
	}

	// Migrate the schema
	db.AutoMigrate(&Book{}, &User{})

	app := fiber.New()

	// Public routes
	app.Post("/register", func(c *fiber.Ctx) error {
		return createUser(db, c)
	})

	app.Post("/login", func(c *fiber.Ctx) error {
		return loginUser(db, c)
	})

	// Protected routes
	app.Use("/books", authRequired)
	// Add your book routes here

	log.Fatal(app.Listen(":8000"))
}
