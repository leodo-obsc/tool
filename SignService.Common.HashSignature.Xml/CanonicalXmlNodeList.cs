using System;
using System.Collections;
using System.Xml;

namespace SignService.Common.HashSignature.Xml
{
    internal class CanonicalXmlNodeList : XmlNodeList, IList, ICollection, IEnumerable
    {
    	private readonly ArrayList m_nodeArray;

    	public override int Count => m_nodeArray.Count;

    	public bool IsFixedSize => m_nodeArray.IsFixedSize;

    	public bool IsReadOnly => m_nodeArray.IsReadOnly;

    	object IList.this[int index]
    	{
    		get
    		{
    			return m_nodeArray[index];
    		}
    		set
    		{
    			if (!(value is XmlNode))
    			{
    				throw new ArgumentException("Cryptography_Xml_IncorrectObjectType");
    			}
    			m_nodeArray[index] = value;
    		}
    	}

    	public object SyncRoot => m_nodeArray.SyncRoot;

    	public bool IsSynchronized => m_nodeArray.IsSynchronized;

    	internal CanonicalXmlNodeList()
    	{
    		m_nodeArray = new ArrayList();
    	}

    	public override XmlNode Item(int index)
    	{
    		return (XmlNode)m_nodeArray[index];
    	}

    	public override IEnumerator GetEnumerator()
    	{
    		return m_nodeArray.GetEnumerator();
    	}

    	public int Add(object value)
    	{
    		if (!(value is XmlNode))
    		{
    			throw new ArgumentException("Cryptography_Xml_IncorrectObjectType");
    		}
    		return m_nodeArray.Add(value);
    	}

    	public void Clear()
    	{
    		m_nodeArray.Clear();
    	}

    	public bool Contains(object value)
    	{
    		return m_nodeArray.Contains(value);
    	}

    	public int IndexOf(object value)
    	{
    		return m_nodeArray.IndexOf(value);
    	}

    	public void Insert(int index, object value)
    	{
    		if (!(value is XmlNode))
    		{
    			throw new ArgumentException("Cryptography_Xml_IncorrectObjectType");
    		}
    		m_nodeArray.Insert(index, value);
    	}

    	public void Remove(object value)
    	{
    		m_nodeArray.Remove(value);
    	}

    	public void RemoveAt(int index)
    	{
    		m_nodeArray.RemoveAt(index);
    	}

    	public void CopyTo(Array array, int index)
    	{
    		m_nodeArray.CopyTo(array, index);
    	}
    }
}
