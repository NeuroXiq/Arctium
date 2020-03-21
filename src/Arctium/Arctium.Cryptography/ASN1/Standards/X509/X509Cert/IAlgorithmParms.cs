﻿using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert
{
    public interface IAlgorithmParms<T>
    {
        T ParamsType { get; }
    }
}
