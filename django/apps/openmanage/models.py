from django.db import models
from django.db import connection, transaction



class Password(models.Model):
    email = models.CharField(max_length=64, primary_key=True)
    pw_hash = models.CharField(max_length=128)

    def update_email(self, new_email):
        cursor = connection.cursor()
        cursor.execute("Delete from passwords where email = %s", [new_email])
        cursor.execute("UPDATE passwords SET email = %s WHERE email = %s", 
                       [new_email, self.email])
        transaction.commit_unless_managed()

    def password_set(self):
        return True if self.pw_hash else False

    class Meta:
        db_table = 'passwords'
