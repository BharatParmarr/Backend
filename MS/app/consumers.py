from django.db import transaction
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async
import django
import json
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MS.settings')
django.setup()


class OrderConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_group_name = 'order_updates'
        self.restorant_id = self.scope['url_route']['kwargs']['restorant_id']
        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()
        if self.restorant_id != '0':
            # Send incomplete orders to the connected client
            incomplete_orders = await self.get_incomplete_orders()
            await self.send(text_data=json.dumps({
                'incomplete_orders': incomplete_orders
            }))
        else:
            await self.send(text_data=json.dumps({
                'message': 'Invalid restorant ID.'
            }))

    async def disconnect(self, close_code):
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        data = json.loads(text_data)
        order_data = data

        # Save the new order and its details
        order = await self.create_order(order_data)
        if order:
            # Broadcast the new order to the group
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'order_update',
                    'order': order
                }
            )
        else:
            await self.send(text_data=json.dumps({
                'message': 'Invalid data from user.'
            }))

    async def order_update(self, event):
        order = event['order']

        # Send the order update to the WebSocket
        await self.send(text_data=json.dumps({
            'order': order
        }))

    @sync_to_async
    def create_order(self, order_data):
        from .models import Item, Order, OrderDetail, Table, BlockIP
        from .serializers import OrderSerializer

        if order_data:
            print(order_data, 'order data')
            ip_address = self.scope['client'][0]
            with transaction.atomic():
                table = Table.objects.get(id=order_data['table'])
                if BlockIP.objects.filter(ip=ip_address, restorant=table.restorant.id).exists():
                    return None
                order_number = Order.objects.filter(
                    table=table, status=False).count()
                order = Order.objects.create(
                    table=table, order_number=order_number + 1, order_ip_address=ip_address)

                for item_data in order_data['items']:
                    item = Item.objects.get(id=item_data['item'])
                    OrderDetail.objects.create(
                        order=order,
                        item=item,
                        quantity=item_data['quantity'],
                        price=item.price,
                        total=item.price * item_data['quantity']
                    )
                return OrderSerializer(order).data
        else:
            return None

    @sync_to_async
    def get_incomplete_orders(self):
        from .models import Order
        from .serializers import OrderSerializer
        incomplete_orders = Order.objects.filter(status=False)[::-1]
        return OrderSerializer(incomplete_orders, many=True).data
