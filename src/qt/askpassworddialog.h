#ifndef ASKPASSWORDDIALOG_H
#define ASKPASSWORDDIALOG_H

#include <QDialog>

namespace Ui {
    class AskPasswordDialog;
}

class WalletModel;

/** Multifunctional dialog to ask for passwords. Used for encryption, unlocking, and changing the password.
 */
class AskPasswordDialog : public QDialog
{
    Q_OBJECT

public:
    enum Mode {
        Encrypt,       /**< Ask password twice and encrypt */
        UnlockStaking, /**< Ask password and unlock */
        Unlock,        /**< Ask password and unlock */
        ChangePass,    /**< Ask old password + new password twice */
        Decrypt        /**< Ask password and decrypt wallet */
    };

    explicit AskPasswordDialog(Mode mode, QWidget *parent = 0);
    ~AskPasswordDialog();

    void accept();

    void setModel(WalletModel *model);

private:
    Ui::AskPasswordDialog *ui;
    Mode mode;
    WalletModel *model;
    bool fCapsLock;

private slots:
    void textChanged();
    bool event(QEvent *event);
    bool eventFilter(QObject *, QEvent *event);
};

#endif // ASKPASSWORDDIALOG_H
