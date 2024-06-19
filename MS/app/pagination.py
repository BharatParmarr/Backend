from rest_framework import pagination

# ordes pagination class
# if you chnage the page size then change the page size in the frontend also in orders view componnet react js


class CustomPagination(pagination.PageNumberPagination):
    page_size = 40
    page_size_query_param = 'page_size'
    max_page_size = 90
    page_query_param = 'page'
