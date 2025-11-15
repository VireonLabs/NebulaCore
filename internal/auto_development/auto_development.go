package auto_development

import (
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "time"
)

type Insight struct {
    Timestamp time.Time
    Category  string
    Message   string
}

type Report struct {
    GeneratedAt time.Time
    Insights    []Insight
}

type AutoDev struct {
    rootPath string
    active   bool // <-- طبقة التفعيل
}

// إنشاء الوحدة (غير مفعّلة)
func New(root string) *AutoDev {
    return &AutoDev{
        rootPath: root,
        active:   false,
    }
}

// تفعيل الوحدة: هذا يتم فقط عندما النموذج يستدعيها
func (a *AutoDev) Activate() {
    a.active = true
}

// حماية الوظائف من أن تعمل بدون تفعيل
func (a *AutoDev) ensureActive() error {
    if !a.active {
        return errors.New("AutoDevelopment module is not activated by the model")
    }
    return nil
}

func (a *AutoDev) ScanStructure() (Report, error) {
    if err := a.ensureActive(); err != nil {
        return Report{}, err
    }

    report := Report{GeneratedAt: time.Now()}

    filepath.Walk(a.rootPath, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            report.Insights = append(report.Insights, Insight{
                Timestamp: time.Now(),
                Category:  "error",
                Message:   "خطأ في قراءة المسار: " + err.Error(),
            })
            return nil
        }

        if !info.IsDir() && info.Size() == 0 {
            report.Insights = append(report.Insights, Insight{
                Timestamp: time.Now(),
                Category:  "empty_file",
                Message:   "تم العثور على ملف فارغ: " + path,
            })
        }

        if strings.HasSuffix(path, ".go") {
            content, _ := os.ReadFile(path)
            if !strings.Contains(string(content), "package ") {
                report.Insights = append(report.Insights, Insight{
                    Timestamp: time.Now(),
                    Category:  "go_warning",
                    Message:   "ملف بدون package: " + path,
                })
            }
        }

        return nil
    })

    return report, nil
}

func (a *AutoDev) Evaluate(rep Report) (Insight, error) {
    if err := a.ensureActive(); err != nil {
        return Insight{}, err
    }

    if len(rep.Insights) == 0 {
        return Insight{
            Timestamp: time.Now(),
            Category:  "status",
            Message:   "لا توجد ملاحظات حالياً",
        }, nil
    }

    return Insight{
        Timestamp: time.Now(),
        Category:  "analysis",
        Message:   fmt.Sprintf("تم العثور على %d ملاحظة للتحسين", len(rep.Insights)),
    }, nil
}
