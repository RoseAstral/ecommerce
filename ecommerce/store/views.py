from django.shortcuts import render, redirect, get_object_or_404
from .form import RegisterForm, LoginUserForm, StoreForm, ProductForm, ReviewForm
from django.contrib.auth.models import User, Group
from django.contrib.auth import login, authenticate, logout
from django.http import HttpResponseRedirect, JsonResponse
from django.urls import reverse
from .models import Store, Product, Review, RestToken, StoreSerializer, ProductSerializer, ReviewSerializer
from django.core.mail import EmailMessage
from datetime import datetime, timedelta
import secrets
from hashlib import sha1
from rest_framework.decorators import api_view
import requests
from .twitter import Tweet

Vendors, created = Group.objects.get_or_create(name='Vendors')
Buyers, created = Group.objects.get_or_create(name='Buyers')

# Create your views here.
def frontpage(request):
    Vendors, created = Group.objects.get_or_create(name='Vendors')
    store_list = Store.objects.all()
    product_list = Product.objects.all()
    cart_products = retreive_porducts(request)
    context = {'store_list': store_list,
               'product_list': product_list,
               'cart_products': cart_products,}
    return render(request, 'store/frontpage.html', context)

def buyer_register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            my_group = Group.objects.get(name='Buyers')
            new_user = form.save(commit=False)
            new_user.save()
            new_user = authenticate(username=form.cleaned_data['username'],
                                    password=form.cleaned_data['password1'])
            login(request, new_user)
            my_group.user_set.add(request.user)
            return redirect('store:frontpage')
    else:
        form = RegisterForm()
    return render(request, "store/register_buyer.html", {'form': form})

def vender_register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            my_group = Group.objects.get(name='Vendors')
            new_user = form.save(commit=False)
            new_user.save()
            new_user = authenticate(username=form.cleaned_data['username'],
                                    password=form.cleaned_data['password1'])
            login(request, new_user)
            my_group.user_set.add(request.user)
            return redirect('store:frontpage')
    else:
        form = RegisterForm()
    return render(request, "store/register_Vender.html", {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = LoginUserForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return HttpResponseRedirect(reverse('store:frontpage'))
    else:
        form = LoginUserForm()
    return render(request, "store/login.html", {'form': form})

def logout_view(request):
    logout(request)
    return redirect('store:frontpage')

def add_store_view(request):
    user = request.user
    if user.has_perm('store.add_store'):
        if request.method == "POST":
            form = StoreForm(request.POST)
            if form.is_valid():
                store = form.save(commit=False)
                store.owner = request.user
                store.save()
                new_tweet = f'New store has been add.\n{store.name}.'
                tweet = {'text': new_tweet}
                Tweet._instance.make_tweet(tweet)
                return redirect("store:frontpage")
        else:
            form = StoreForm()
        return render(request, "store/add_store.html", {"form": form})
    else:
        return HttpResponseRedirect(reverse('store:frontpage'))
        

def update_store_view(request, pk):
    user = request.user
    if user.has_perm('store.change_store'):
        store = get_object_or_404(Store, pk=pk)
        if request.method == "POST":
            form = StoreForm(request.POST, instance=store)
            if form.is_valid():
                store = form.save(commit=False)
                store.save()
                return redirect("store:frontpage")
        else:
            form = StoreForm(instance=store)
        return render(request, "store/add_store.html", {"form": form})
    else:
        return HttpResponseRedirect(reverse('store:frontpage'))

def delete_store_view(request, pk):
    user = request.user
    if user.has_perm('store.delete_store'):
        post = get_object_or_404(Store, pk=pk)
        post.delete()
        return redirect("store:frontpage")
    else:
        return HttpResponseRedirect(reverse('store:frontpage'))

def add_product_view(request, pk):
    user = request.user
    if user.has_perm('store.add_product'):
        if request.method == "POST":
            form = ProductForm(request.POST)
            if form.is_valid():
                product = form.save(commit=False)
                product.store = Store.objects.get(pk=pk)
                product.seller = request.user
                product.save()
                new_product_tweet = f'New product has been add.\n{product.label}\nOn{product.store.name}.'
                tweet = {'text': new_product_tweet}
                Tweet._instance.make_tweet(tweet)
                return redirect("store:frontpage")
        else:
            form = ProductForm()
        return render(request, "store/add_product.html", {"form": form})
    else:
        return HttpResponseRedirect(reverse('store:frontpage'))

def update_product_view(request, pk):
    user = request.user
    if user.has_perm('store.change_product'):
        product = get_object_or_404(Product, pk=pk)
        if request.method == "POST":
            form = ProductForm(request.POST, instance=product)
            if form.is_valid():
                product = form.save(commit=False)
                product.save()
                return redirect("store:frontpage")
        else:
            form = ProductForm(instance=product)
        return render(request, "store/add_product.html", {"form": form})
    else:
        return HttpResponseRedirect(reverse('store:frontpage'))

def delete_product_view(request, pk):
    user = request.user
    if user.has_perm('store.delete_product'):
        post = get_object_or_404(Product, pk=pk)
        post.delete()
        return redirect("store:frontpage")
    else:
        return HttpResponseRedirect(reverse('store:frontpage'))

def store_details_view(request, pk):
    store_list = Store.objects.all()
    product_list = Product.objects.all()
    store = get_object_or_404(Store, pk=pk)
    filtered_products = Product.objects.filter(store=store)
    context = {'store_list': store_list,
               'product_list': product_list,
               'store': store,
               'filtered_products': filtered_products}
    return render(request, "store/store_details.html", context)

def product_details_view(request, pk):
    review_list = Review.objects.all()
    product = get_object_or_404(Product, pk=pk)
    context = {'product': product, 'review_list': review_list}
    return render(request, "store/product_details.html", context)

def add_review_view(request, pk):
    if request.method == "POST":
        form = ReviewForm(request.POST)
        if form.is_valid():
            review = form.save(commit=False)
            review.product = Product.objects.get(pk=pk)
            review.save()
            return redirect("store:frontpage")
    else:
        form = ReviewForm()
    return render(request, "store/add_comment.html", {"form": form})

def add_item_to_cart_view(request, pk): 
    session = request.session
    item = get_object_or_404(Product, pk=pk)
    item_s = item.pk
    if 'cart' not in request.session:
        session['cart'] = [item_s]
    else:
        saved_list = session['cart']
        saved_list.append(item_s)
        session['cart'] = saved_list
    return redirect("store:frontpage")

def retreive_porducts(request):
    session = request.session
    product_pk = session.get('cart', [])
    products = Product.objects.filter(pk__in=product_pk)
    return products
            

def view_cart_view(request):
    cart = retreive_porducts(request)
    return render(request, 'store/cart.html', {'cart': cart})

def build_invoice(user):
    subject = "Ecommerece Invoice"
    user_email = user.email
    domain_email = "example@domain.com"
    body = f"Hi {user.username}, \nThank you for your purchase"
    email = EmailMessage(subject, body, domain_email, [user_email])
    return email

def send_invoice(request):
    user_email = User.email
    email = build_invoice(user_email)
    email.send()
    return HttpResponseRedirect(reverse('store:frontpage'))

def build_reset_email(user, reset_url):
    subject = "Ecommerece Invoice"
    user_email = user.email
    domain_email = "example@domain.com"
    body = f"Hi {user.username}, \nHere is the password reset link {reset_url}"
    email = EmailMessage(subject, body, domain_email, [user_email])
    return email

def generate_reset_url(user):
    domain = "http://127.0.0.1:8000/"
    app_name = 'Store'
    url = f"{domain}{app_name}/reset_password"
    token =str(secrets.token_urlsafe(16))
    expiry_date = datetime.now() + timedelta(minutes=5)
    reset_token = RestToken.objects.create(user=user, token=sha1(token.encode()).hexdigest(), expiry_date=expiry_date)
    url += f"{token}/"
    return url

def send_password_reset(request): 
    user_email = request.POST.get('email') 
    user = User.objects.get(email=user_email) 
    url = generate_reset_url(user) 
    email = build_reset_email(user, url) 
    email.send() 
    return HttpResponseRedirect(reverse('store:login'))

def reset_user_password(request, token):
    try:
        sha1(token.encode()).hexdigest()
        user_token = RestToken.objects.get(token=sha1(token.encode()).hexdigest())
        if user_token.expiry_date.replace(tzinfo=None) < datetime.now():
            user_token.delete()
        request.session['user'] = user_token.user.username
        request.session['token'] = token
    except:
        user_token = None 
    return render(request, 'password_reset.html', {'token':user_token})

def reset_password(request):
    username = request.session['user']
    token = request.session['token']
    password = request.POST.get('password')
    password_conf = request.POST.get('password_conf')
    if password == password_conf:
        change_user_password(username, password)
        
        RestToken.objects.get(token=sha1(token.encode()).hexdigest()).delete()
        return HttpResponseRedirect(reverse('store:login'))
    else:
        return HttpResponseRedirect(reverse('store:password_reset'))

def change_user_password(username, new_password):
    user = User.objects.get(username=username)
    user.set_password(new_password)
    user.save()

@api_view(['POST'])
@authentication_classes([BasicAuthentication])
@permission_classes([IsAuthenticated])
def add_store_api_view(request): 
    if request.method == "POST":
        serializer = StoreSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            new_tweet = f'New store has been add.\n{serializer.name}.'
            tweet = {'text': new_tweet}
            Tweet._instance.make_tweet(tweet)
            return JsonResponse(data=serializer.data, status=status.HTTP_201_CREATED)
        return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['GET'])
def view_store_api_view(request):
    if request.method == "GET":
        serializer = StoreSerializer(Store.objects.all(), many=True)
        return JsonResponse(data=serializer.data, safe=False)
    
@api_view(['POST'])
@authentication_classes([BasicAuthentication])
@permission_classes([IsAuthenticated])
def add_product_api_view(request): 
    if request.method == "POST":
        serializer = ProductSerializer(data=request.data)
        if serializer.is_valid():
            new_tweet = f'New product has been add.\n{serializer.name}\nOn{serializer.store.name}.'
            tweet = {'text': new_tweet}
            Tweet._instance.make_tweet(tweet)
            serializer.save()
            return JsonResponse(data=serializer.data, status=status.HTTP_201_CREATED)
        return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['GET'])
def view_product_api_view(request):
    if request.method == "GET":
        serializer = ProductSerializer(Product.objects.all(), many=True)
        return JsonResponse(data=serializer.data, safe=False)
    
@api_view(['GET'])
def view_review_api_view(request):
    if request.method == "GET":
        serializer = ReviewSerializer(Review.objects.all(), many=True)
        return JsonResponse(data=serializer.data, safe=False)