from functools import wraps
import inspect
import cchardet
import traceback


class TypeTool:
    """
    类型工具类
    """

    @classmethod
    def type_assert(cls, func):
        """
        类型断言
        :param func: 要装饰的函数
        :return:
        """

        def check_arg(arg, tp):
            """
            检查参数
            :param arg: 传进来的参数
            :param tp: 要检查的参数类型，是一个列表，需要为其中的一种
            :return:
            """
            if hasattr(tp, '__origin__'):
                if tp.__origin__ is None:  # 有__origin__属性，但是是None
                    return isinstance(arg, tp)  # 直接判断是否为指定类型
                else:
                    if tp.__args__ is not None:
                        if tp.__origin__ in [tuple, list, set, frozenset]:
                            if isinstance(arg, tp.__origin__):
                                if len(arg) == len(tp.__args__):  # 判断所有的类型
                                    return all([check_arg(inner_arg, inner_type) for inner_arg, inner_type in
                                                zip(arg, tp.__args__)])
                                else:
                                    return False
                            else:
                                return False
                        else:
                            return isinstance(arg, tp.__origin__)
                    else:  # 判断参数是否为原始类型
                        return isinstance(arg, tp.__origin__)
            else:
                # 重点：不是origin类型
                if type(tp) in [list, tuple]:
                    for oneTp in tp:
                        # 递归检查参数，如果是其中一种参数，则通过
                        if check_arg(arg, oneTp):
                            return True
                    return False
                else:  # 单独的一个参数，只需要检查是否为指定类型
                    return isinstance(arg, tp)

        @wraps(func)
        def wrapper(*args, **kwargs):
            signature = inspect.signature(func)
            parameters = signature.parameters
            keys = parameters.keys()
            for arg, key in zip(args, keys):
                if parameters[key].annotation != inspect._empty:
                    assert check_arg(arg,
                                     parameters[key].annotation), 'Argument {} is type {} but should be type {}'.format(
                        key, type(arg), parameters[key].annotation)

            for key in kwargs.keys():
                if parameters[key].annotation != inspect._empty:
                    assert check_arg(kwargs[key], parameters[
                        key].annotation), 'Key word argument {} is type {} but should be type {}'.format(key, type(
                        kwargs[key]), parameters[key].annotation)
            out = func(*args, **kwargs)
            if signature.return_annotation != inspect._empty:
                if signature.return_annotation is None:
                    assert out is None, 'Return type {} should be None'.format(type(out))
                else:
                    assert check_arg(out, signature.return_annotation), 'Return type {} should be type {}'.format(
                        type(out), signature.return_annotation)
            return out

        return wrapper

    @classmethod
    def type_sbb_2_bytes(cls, sbb):
        """
        将其他数据类型转换为bytes类型
        :param sbb: 其他数据
        :return:
        """
        # 创建一个字节数组
        b = bytes()

        # 断言字节类型
        assert type(sbb) in [str, bytes, bytearray], \
            'Argument {} is type {} but should be type {}'. \
                format(sbb, type(sbb), "[str,bytes,bytearray]")

        # 转换数据类型
        if type(sbb) == str:
            b = bytes(sbb, 'utf-8')
        else:
            b = bytes(sbb)

        # 返回转换后的数据
        return b

    @classmethod
    def type_sbb_2_str(cls, sbb, decode_way=''):
        s = ''
        try:
            assert type(sbb) in [str, bytes, bytearray], 'Argument {} is type {} but should be type {}'.format(sbb,
                                                                                                               type(
                                                                                                                   sbb),
                                                                                                               "[str,bytes,bytearray]")
            assert type(decode_way) in [str], 'Argument {} is type {} but should be type {}'.format(decode_way,
                                                                                                    type(decode_way),
                                                                                                    "str")
            if type(s) == str:
                return sbb
            # 尝试识别和获取编码
            if decode_way == '':
                decode_way = cchardet.detect(sbb)['encoding']
            # 使用已获取到的编码进行尝试解码
            if decode_way != '':
                try:
                    s = sbb.decode(decode_way)  # 严格解析
                except:
                    s = sbb.decode(decode_way, 'ignore')  # 忽略错误解析，decode_way可能也不合法
        except:
            traceback.print_exc()
        if s == '':
            # 强制转换，只有当之前的尝试都失败时才会触发
            s = str(sbb)[2:-1].replace('\\\\', '\\').replace("\\'", "'")
        return s
