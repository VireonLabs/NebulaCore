package marketplace

import (
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "time"
)

type Plugin struct {
    Name      string
    Version   string
    InstalledAt time.Time
}

type Marketplace struct {
    storagePath string
    plugins     map[string]Plugin
}

func NewMarketplace(storage string) *Marketplace {
    os.MkdirAll(storage, 0755)
    return &Marketplace{
        storagePath: storage,
        plugins:     make(map[string]Plugin),
    }
}

func (m *Marketplace) InstallLocal(path string) (Plugin, error) {
    if _, err := os.Stat(path); err != nil {
        return Plugin{}, errors.New("الملف غير موجود")
    }

    name := filepath.Base(path)
    p := Plugin{Name: name, Version: "0.1", InstalledAt: time.Now()}
    m.plugins[name] = p

    return p, nil
}

func (m *Marketplace) List() []Plugin {
    out := []Plugin{}
    for _, p := range m.plugins {
        out = append(out, p)
    }
    return out
}

func (m *Marketplace) Info(name string) (Plugin, error) {
    p, ok := m.plugins[name]
    if !ok {
        return Plugin{}, fmt.Errorf("الملحق غير مثبت: %s", name)
    }
    return p, nil
}
