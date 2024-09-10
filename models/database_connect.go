package models

import (
	"github.com/asdine/storm/v3"
)

const DATABASE_NAME = "./bolt.db"

// Conecta a la base de datos
func dbConnect() (db *storm.DB, err error) {
	return storm.Open(DATABASE_NAME)
}

// Inicializa la base de datos
func InitDatabase() (err error) {

	bolt, err := storm.Open(DATABASE_NAME)
	if err != nil {
		return err
	}
	defer bolt.Close()
	// Inicializamos las estructuras de datos
	err = bolt.Init(&User{})
	if err != nil {
		return err
	}

	err = bolt.Init(&clientDB{})
	if err != nil {
		return err
	}

	err = bolt.Init(&accessTokenDB{})
	if err != nil {
		return err
	}

	err = bolt.Init(&refreshTokenDB{})
	if err != nil {
		return err
	}

	return nil
}
