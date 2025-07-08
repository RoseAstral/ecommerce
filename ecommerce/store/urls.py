from django.urls import path
from .views import  (
    buyer_register_view,
    frontpage,
    vender_register_view,
    login_view,
    add_store_view,
    update_store_view,
    delete_store_view,
    logout_view,
    add_product_view,
    update_product_view,
    delete_product_view,
    store_details_view,
    product_details_view,
    add_review_view,
    add_item_to_cart_view,
    view_cart_view,
    send_invoice,
    reset_user_password,
    send_password_reset,
)

app_name = "store"
urlpatterns = [
    path('send_password_resest', send_password_reset, name='send_reset'),

    path('send_invoice/', send_invoice, name="send_invoice"),

    path('reset_password/<str:token>/', reset_user_password, name='password_reset'),

    path('cart/', view_cart_view, name="view_cart"),

    path('add_to_cart/<int:pk>/', add_item_to_cart_view, name='add_to_cart'),
    
    path('product_details/<int:pk>/add_review/', add_review_view, name='add_review'),

    path('product_details/<int:pk>/', product_details_view, name='product_details'),
    
    path('store_details/<int:pk>/', store_details_view, name="store_details"),

    path('delete_product/<int:pk>/', delete_product_view, name='delete_product'),

    path('edit_product/<int:pk>/', update_product_view, name="edit_product"),

    path('store_details/<int:pk>/add_product/', add_product_view, name='add_product'),

    path('logout/', logout_view, name='logout'),

    path('delete_store/<int:pk>/', delete_store_view, name='delete_store'),

    path('edit_store/<int:pk>/', update_store_view, name="edit_store"),

    path("add_store/", add_store_view, name="add_store"),

    path("login/", login_view, name="login"),

    path("registervender/", vender_register_view, name="vender_register"),

    path("", frontpage, name="frontpage"),
    
    path("registerbuyer/", buyer_register_view, name="buyer_register")

]
