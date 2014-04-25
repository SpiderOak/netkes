from django.db import models


class Password(models.Model):
    email = models.CharField(max_length=64, primary_key=True)
    pw_hash = models.CharField(max_length=128)

    def password_set(self):
        return True if self.pw_hash else False

    class Meta:
        db_table = 'passwords'
