from django.contrib.auth.models import User
from django.forms import ModelForm
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django import forms
from .models import Store, Product, Review


class RegisterForm(UserCreationForm):
    email = forms.EmailField()

    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name', 'password1', 'password2']


class LoginUserForm(AuthenticationForm):
    pass


class StoreForm(forms.ModelForm):
    class Meta:
        model = Store
        fields = ['name']


class ProductForm(forms.ModelForm):
    class Meta:
        model = Product
        fields = ['label', 'description', 'price']


class ReviewForm(forms.ModelForm):
    class Meta:
        model = Review
        fields =['title', 'content']
