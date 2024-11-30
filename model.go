package main

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type Book struct {
	gorm.Model
	Name        string `json:"name"`
	Author      string `json:"author"`
	Description string `json:"description"`
}

type User struct {
	gorm.Model
	Email    string `gorm:"unique;not null" json:"email"`
	Password string `json:"password"`
}

type LoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func createUser(db *gorm.DB, c *fiber.Ctx) error {
	var user User
	if err := c.BodyParser(&user); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "ข้อมูลไม่ถูกต้อง",
		})
	}

	if user.Email == "" || user.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "กรุณากรอกอีเมลและรหัสผ่าน",
		})
	}

	var existingUser User
	if err := db.Where("email = ?", user.Email).First(&existingUser).Error; err == nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"message": "อีเมลนี้ถูกใช้งานแล้ว",
		})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "เกิดข้อผิดพลาดในการสร้างผู้ใช้",
		})
	}
	user.Password = string(hashedPassword)

	if err := db.Create(&user).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "เกิดข้อผิดพลาดในการสร้างผู้ใช้",
		})
	}

	user.Password = "" // ลบรหัสผ่านออกจากการตอบกลับ
	return c.Status(fiber.StatusCreated).JSON(user)
}

func loginUser(db *gorm.DB, c *fiber.Ctx) error {
	var input LoginInput
	var user User

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "ข้อมูลไม่ถูกต้อง",
		})
	}

	if err := db.Where("email = ?", input.Email).First(&user).Error; err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "อีเมลหรือรหัสผ่านไม่ถูกต้อง",
		})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "อีเมลหรือรหัสผ่านไม่ถูกต้อง",
		})
	}

	// สร้าง claims ใหม่โดยใช้ RegisteredClaims
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Subject:   fmt.Sprintf("%d", user.ID),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour * 72)),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		Issuer:    "your-app-name",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	t, err := token.SignedString(jwtSecretKey)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "เกิดข้อผิดพลาดในการสร้าง token",
		})
	}

	c.Cookie(&fiber.Cookie{
		Name:     "jwt",
		Value:    t,
		Expires:  now.Add(time.Hour * 72),
		HTTPOnly: true,
		Secure:   true, // เปิดใช้ในระบบจริง
		SameSite: "Lax",
	})

	return c.JSON(fiber.Map{
		"message": "เข้าสู่ระบบสำเร็จ",
		"token":   t,
	})
}
