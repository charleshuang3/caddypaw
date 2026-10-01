package statisfiles

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/gin-gonic/gin"
)

//go:embed res/*
var staticFiles embed.FS

func RegisterHandlers(rg *gin.RouterGroup) {
	staticFiles, _ := fs.Sub(staticFiles, "res")
	rg.StaticFS("/static", http.FS(staticFiles))
}
