from django.db import models
from django.conf import settings
from rest_framework import serializers

# Create your models here.
class Store(models.Model):
    name = models.CharField(max_length=255)
    owner = models.CharField(max_length=255)


class Product(models.Model):
    store = models.ForeignKey(Store, related_name='product', on_delete=models.CASCADE, default=None)
    label = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=5, decimal_places=2)
    seller = models.CharField(max_length=255)


class Review(models.Model):
    product = models.ForeignKey(Product, related_name='reviews', on_delete=models.CASCADE)
    title = models.CharField(max_length=255, default=None)
    content = models.TextField()


class RestToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,)
    token = models.CharField(max_length=500)
    expiry_date = models.DateTimeField()
    used = models.BooleanField(default=False)


class StoreSerializer(serializers.ModelSerializer):
    class Meta:
        model = Store
        fields = ['owner', 'name',]

class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ['store', 'label', 'description', 'price', 'seller' ]

class ReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Review
        fields = ['product', 'title', 'content']